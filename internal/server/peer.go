// Package server: Phase 4 per-peer state.
//
// A Peer represents one (clientID, encryptionKey, link.Link, smux.Session)
// tuple. The Server holds a slice of *Peer once Task 4.5 lands. Each Peer
// owns its own WebRTC PeerConnection, ICE state, crypto key, and smux
// multiplexer — peers in the same room do not share any of these.
package server

import (
	"context"
	"sync"

	"github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/link"
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

	mu      sync.RWMutex
	closed  bool
	cancel  context.CancelFunc
	readyCh chan struct{}
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
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.Session != nil {
		_ = p.Session.Close()
	}
	if p.Mux != nil {
		_ = p.Mux.Close()
	}
	if p.Link != nil {
		_ = p.Link.Close()
	}
	if p.cancel != nil {
		p.cancel()
	}
}
