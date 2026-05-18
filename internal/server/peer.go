// Package server: Phase 4 per-peer state.
//
// A Peer represents one (clientID, encryptionKey, link.Link, smux.Session)
// tuple. The Server holds a slice of *Peer once Task 4.5 lands. Each Peer
// owns its own WebRTC PeerConnection, ICE state, crypto key, and smux
// multiplexer — peers in the same room do not share any of these.
package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/handshake"
	"github.com/openlibrecommunity/olcrtc/internal/link"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/muxconn"
	"github.com/xtaci/smux"
)

// PeerConfig is one entry in the multi-peer slice. Loaded from yaml
// (Task 4.6) or built in tests.
type PeerConfig struct {
	ClientID string
	Key      []byte // 32 raw bytes (AES-256)
}

// Peer is the per-client runtime state inside Server.
type Peer struct {
	ClientID      string
	EncryptionKey []byte

	Link    link.Link
	Cipher  *crypto.Cipher
	Mux     *muxconn.Conn
	Session *smux.Session

	// parent points back to the Server for shared hooks (authHook, onOpen,
	// onClose, onTraffic) and shared config (DNS resolver, SOCKS proxy).
	// Set during NewPeer or Server.startPeer.
	parent *Server

	mu          sync.RWMutex
	reinstallMu sync.Mutex
	closed      bool
	readyCh     chan struct{}
	sessionID   string // populated after handshake
	deviceID    string
}

// NewPeer creates a Peer ready to be wired by Server.startPeer (Task 4.5).
func NewPeer(clientID string, key []byte) *Peer {
	return &Peer{
		ClientID:      clientID,
		EncryptionKey: key,
		readyCh:       make(chan struct{}),
	}
}

// Ready returns a channel that closes once the peer is connected to the
// SFU room and its smux session is installed.
func (p *Peer) Ready() <-chan struct{} { return p.readyCh }

// Close tears down the peer's link + smux session. Idempotent.
func (p *Peer) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	parent := p.parent
	p.mu.Unlock()
	// closeSession handles session+conn nilling + onClose hook.
	p.closeSession()
	p.mu.Lock()
	ln := p.Link
	p.Link = nil
	p.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	if parent != nil && parent.sessions != nil {
		parent.sessions.Unregister(p.ClientID)
	}
}

// setupCipher decodes the AES key bytes and creates this peer's cipher.
// Called once per peer during startPeer.
func (p *Peer) setupCipher() error {
	if len(p.EncryptionKey) != 32 {
		return fmt.Errorf("%w, got %d", ErrKeySize, len(p.EncryptionKey))
	}
	cipher, err := crypto.NewCipher(string(p.EncryptionKey))
	if err != nil {
		return fmt.Errorf("crypto.NewCipher: %w", err)
	}
	p.Cipher = cipher
	return nil
}

// onData is the link.Link OnData callback. Pushes incoming bytes into
// this peer's muxconn, which decrypts them with this peer's key. Frames
// from peers using a different key produce decryption errors at the
// muxconn layer and are silently dropped — this is the natural
// per-peer filter that makes multi-peer-in-one-room work.
func (p *Peer) onData(data []byte) {
	p.mu.RLock()
	mux := p.Mux
	p.mu.RUnlock()
	if mux != nil {
		mux.Push(data)
	}
}

// installSession creates a fresh muxconn (with peer's cipher) and smux
// server. Replaces the previous (if any) under reinstallMu.
func (p *Peer) installSession() {
	newConn := muxconn.New(p.Link, p.Cipher)
	newSess, err := smux.Server(newConn, smuxConfig())
	if err != nil {
		logger.Warnf("peer %s: smux server init failed: %v", p.ClientID, err)
		_ = newConn.Close()
		return
	}
	p.mu.Lock()
	p.Mux = newConn
	p.Session = newSess
	p.mu.Unlock()
}

// handleReconnect tears down peer's current smux/muxconn (called via
// link.SetReconnectCallback after a carrier reconnect on THIS peer's
// link), then reinstalls a fresh session.
func (p *Peer) handleReconnect() {
	logger.Infof("peer %s: link reconnect - tearing down smux session", p.ClientID)
	p.mu.RLock()
	current := p.Session
	p.mu.RUnlock()
	p.reinstallSession(current)
}

// reinstallSession swaps out dead session for a new one. Atomic with
// respect to other concurrent reinstall calls.
func (p *Peer) reinstallSession(dead *smux.Session) {
	p.reinstallMu.Lock()
	defer p.reinstallMu.Unlock()

	newConn := muxconn.New(p.Link, p.Cipher)
	newSess, err := smux.Server(newConn, smuxConfig())
	if err != nil {
		logger.Warnf("peer %s: smux server init failed: %v", p.ClientID, err)
		_ = newConn.Close()
		return
	}
	p.mu.Lock()
	if p.Session != dead {
		p.mu.Unlock()
		_ = newSess.Close()
		_ = newConn.Close()
		return
	}
	oldSess := p.Session
	oldConn := p.Mux
	oldSID := p.sessionID
	p.Session = newSess
	p.Mux = newConn
	p.sessionID = ""
	p.deviceID = ""
	p.mu.Unlock()

	if oldSess != nil {
		_ = oldSess.Close()
	}
	if oldConn != nil {
		_ = oldConn.Close()
	}
	if oldSID != "" && p.parent != nil {
		p.parent.onClose(oldSID, "reconnect")
	}
	// Release the vp8channel first-peer lock so the next peer reconnect
	// can latch onto a fresh epoch. Without this, the lock stays pinned
	// to the dead session's peer epoch and every subsequent reconnect
	// gets dropped as "foreign peer". Optional-interface, no-op for
	// links/transports that don't support it.
	resetPeerLock(p.Link)
}

// closeSession tears down this peer's session and reports onClose with
// reason="closed". Called from Peer.Close and from Server.Shutdown via
// Close. Idempotent vs Close (which calls this too).
func (p *Peer) closeSession() {
	p.mu.Lock()
	sess := p.Session
	conn := p.Mux
	p.Session = nil
	p.Mux = nil
	oldSID := p.sessionID
	p.sessionID = ""
	p.deviceID = ""
	p.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
	if sess != nil {
		_ = sess.Close()
	}
	if oldSID != "" && p.parent != nil {
		p.parent.onClose(oldSID, "closed")
	}
	resetPeerLock(p.Link)
}

// resetPeerLock invokes Link.ResetPeerLock() if implemented (vp8channel
// via directLink). Centralised so reinstallSession + closeSession stay
// in sync.
func resetPeerLock(ln any) {
	if r, ok := ln.(interface{ ResetPeerLock() }); ok {
		r.ResetPeerLock()
	}
}

// handshakeReady reports whether this peer's current session has
// completed its handshake.
func (p *Peer) handshakeReady() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sessionID != ""
}

// acceptHandshake accepts the first stream on the peer's session, runs
// the auth handshake, and parks the control stream. Returns false if
// the handshake failed (caller should reinstall).
func (p *Peer) acceptHandshake(ctx context.Context, sess *smux.Session) bool {
	stream, err := sess.AcceptStream()
	if err != nil {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		logger.Debugf("peer %s: AcceptStream(control) returned %v - reinstalling session", p.ClientID, err)
		p.reinstallSession(sess)
		return false
	}
	_ = stream.SetDeadline(time.Now().Add(handshake.DefaultTimeout))
	hook := p.parent.authHook
	hello, sid, err := handshake.Server(stream, hook)
	_ = stream.SetDeadline(time.Time{})
	if err != nil {
		logger.Warnf("peer %s: handshake failed: %v", p.ClientID, err)
		_ = stream.Close()
		p.reinstallSession(sess)
		return false
	}
	p.mu.Lock()
	p.deviceID = hello.DeviceID
	p.sessionID = sid
	p.mu.Unlock()
	p.parent.onOpen(sid, hello.DeviceID, hello.Claims)
	logger.Infof("peer %s: session %s opened (device=%s)", p.ClientID, sid, hello.DeviceID)
	// Park the control stream in a goroutine.
	p.parent.wg.Add(1)
	go func() {
		defer p.parent.wg.Done()
		p.parkControlStream(stream)
	}()
	return true
}

func (p *Peer) parkControlStream(stream *smux.Stream) {
	defer func() { _ = stream.Close() }()
	buf := make([]byte, 64)
	for {
		if _, err := stream.Read(buf); err != nil {
			return
		}
	}
}

// serve runs the per-peer smux Accept loop — same logic as the old
// Server.serve but bound to this peer's session.
func (p *Peer) serve(ctx context.Context) {
	for {
		if contextDone(ctx) {
			return
		}
		p.mu.RLock()
		sess := p.Session
		p.mu.RUnlock()
		if sess == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
				continue
			}
		}
		if !p.handshakeReady() {
			if !p.acceptHandshake(ctx, sess) {
				continue
			}
		}
		stream, err := sess.AcceptStream()
		if err != nil {
			if contextDone(ctx) {
				return
			}
			logger.Debugf("peer %s: AcceptStream returned %v - reinstalling session", p.ClientID, err)
			p.reinstallSession(sess)
			continue
		}
		// Snapshot the sessionID for this stream's traffic attribution.
		p.mu.RLock()
		sid := p.sessionID
		p.mu.RUnlock()
		p.parent.wg.Add(1)
		go func() {
			defer p.parent.wg.Done()
			p.parent.handleStream(ctx, stream, sid)
		}()
	}
}
