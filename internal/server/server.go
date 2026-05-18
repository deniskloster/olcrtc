// Package server implements the olcrtc tunnel server logic.
package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/handshake"
	"github.com/openlibrecommunity/olcrtc/internal/link"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/names"
	"github.com/xtaci/smux"
)

const connectCommand = "connect"

var (
	// ErrKeyRequired is returned when no encryption key is provided.
	ErrKeyRequired = errors.New("key required (use -key <hex>)")
	// ErrKeySize is returned when the encryption key is not 32 bytes.
	ErrKeySize = errors.New("key must be 32 bytes")
	// ErrSocks5AuthFailed is returned when SOCKS5 authentication fails.
	ErrSocks5AuthFailed = errors.New("SOCKS5 auth failed")
	// ErrSocks5ConnectFailed is returned when SOCKS5 connection fails.
	ErrSocks5ConnectFailed = errors.New("SOCKS5 connect failed")
)

// SessionOpenFunc is called after a successful handshake, before the server
// accepts tunnel streams on that session.
type SessionOpenFunc func(sessionID, deviceID string, claims map[string]any)

// SessionCloseFunc is called when a session is torn down. Possible reasons:
// "reconnect" (carrier dropped and was reestablished), "closed" (graceful
// shutdown or ctx cancel).
type SessionCloseFunc func(sessionID, reason string)

// TrafficFunc is called once per tunnel stream, after the copy loops finish.
// bytesIn counts client→target bytes; bytesOut counts target→client bytes.
type TrafficFunc func(sessionID, addr string, bytesIn, bytesOut uint64)

// Server handles incoming tunnel connections and proxies their traffic.
// After Phase 4 (Task 4.5), Server owns N *Peer instances — each peer has
// its own link.Link + muxconn + smux.Session + per-peer AES cipher. Per-peer
// cipher mismatch naturally filters foreign-peer frames arriving via the
// SFU broadcast.
type Server struct {
	// hooks shared across all peers
	authHook  handshake.AuthFunc
	onOpen    SessionOpenFunc
	onClose   SessionCloseFunc
	onTraffic TrafficFunc

	// shared config
	dnsServer      string
	resolver       *net.Resolver
	socksProxyAddr string
	socksProxyPort int

	// peer state
	peers    []*Peer
	peersMu  sync.RWMutex
	sessions *Sessions

	wg sync.WaitGroup
}

// ConnectRequest is a message from the client to establish a new connection.
type ConnectRequest struct {
	Cmd  string `json:"cmd"`
	Addr string `json:"addr"`
	Port int    `json:"port"`
}

// Config holds runtime configuration for [Run].
type Config struct {
	Link            string
	Transport       string
	Carrier         string
	RoomURL         string
	KeyHex          string
	DNSServer       string
	SOCKSProxyAddr  string
	SOCKSProxyPort  int
	VideoWidth      int
	VideoHeight     int
	VideoFPS        int
	VideoBitrate    string
	VideoHW         string
	VideoQRSize     int
	VideoQRRecovery string
	VideoCodec      string
	VideoTileModule int
	VideoTileRS     int
	VP8FPS          int
	VP8BatchSize    int
	SEIFPS          int
	SEIBatchSize    int
	SEIFragmentSize int
	SEIAckTimeoutMS int
	Engine          string
	URL             string
	Token           string

	// Peers is the Phase 4 multi-peer slice. If non-empty it takes
	// precedence over KeyHex; each entry spawns its own link.Link +
	// smux.Session bound to its own AES key. If empty, KeyHex is used
	// to build a single "default" peer (back-compat with Phase 1-3
	// single-peer callers like e2e tests and the docker olcrtc-server).
	Peers []PeerConfig

	// AuthHook is invoked after CLIENT_HELLO to authorize the client and
	// return a session ID. If nil, every client is admitted with a random UUID.
	AuthHook handshake.AuthFunc

	// OnSessionOpen fires after a successful handshake. Nil means no-op.
	OnSessionOpen SessionOpenFunc
	// OnSessionClose fires when the session is torn down (reconnect, closed). Nil means no-op.
	OnSessionClose SessionCloseFunc
	// OnTraffic fires once per tunnel stream after both copy loops finish. Nil means no-op.
	OnTraffic TrafficFunc
}

// Run starts the server with the given configuration.
func Run(ctx context.Context, cfg Config) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	peerCfgs, err := buildPeerConfigs(cfg)
	if err != nil {
		return fmt.Errorf("build peers: %w", err)
	}

	hook := cfg.AuthHook
	if hook == nil {
		hook = defaultAuthHook
	}
	onOpen := cfg.OnSessionOpen
	if onOpen == nil {
		onOpen = func(string, string, map[string]any) {}
	}
	onClose := cfg.OnSessionClose
	if onClose == nil {
		onClose = func(string, string) {}
	}
	onTraffic := cfg.OnTraffic
	if onTraffic == nil {
		onTraffic = func(string, string, uint64, uint64) {}
	}

	s := &Server{
		authHook:       hook,
		onOpen:         onOpen,
		onClose:        onClose,
		onTraffic:      onTraffic,
		dnsServer:      cfg.DNSServer,
		socksProxyAddr: cfg.SOCKSProxyAddr,
		socksProxyPort: cfg.SOCKSProxyPort,
		sessions:       NewSessions(),
	}
	s.setupResolver()

	if err := s.bringUpPeers(runCtx, peerCfgs, cfg, cancel); err != nil {
		s.shutdown()
		s.wg.Wait()
		return err
	}

	go func() {
		<-runCtx.Done()
		s.shutdown()
	}()

	// Block until all peers' serve loops (and helpers) exit.
	s.wg.Wait()

	return nil
}

// buildPeerConfigs normalizes cfg.Peers + legacy cfg.KeyHex into a slice
// of PeerConfig. If cfg.Peers is non-empty, use it directly. Otherwise
// fall back to KeyHex as a single "default" peer.
func buildPeerConfigs(cfg Config) ([]PeerConfig, error) {
	if len(cfg.Peers) > 0 {
		return cfg.Peers, nil
	}
	if cfg.KeyHex == "" {
		return nil, ErrKeyRequired
	}
	key, err := hex.DecodeString(cfg.KeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode KeyHex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%w, got %d", ErrKeySize, len(key))
	}
	return []PeerConfig{{ClientID: "default", Key: key}}, nil
}

// setupCipher decodes the hex key and creates a cipher. Retained for
// existing test coverage (TestSetupCipher, TestSetupCipherRejectsBadInput).
// Production callers go through buildPeerConfigs + Peer.setupCipher.
func setupCipher(keyHex string) (*crypto.Cipher, error) {
	if keyHex == "" {
		return nil, ErrKeyRequired
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%w, got %d", ErrKeySize, len(key))
	}

	cipher, err := crypto.NewCipher(string(key))
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	return cipher, nil
}

func (s *Server) setupResolver() {
	s.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, s.dnsServer)
		},
	}
}

// smuxConfig mirrors the client side. Both peers must agree on Version and
// MaxFrameSize.
//
// KeepAlive enabled 2026-05-18: was previously disabled because vp8channel
// layer was assumed reliable enough that smux didn't need its own liveness
// pings. That assumption broke on Telemost: when a client tears down its
// tunnel, its Pion WebRTC peer can keep publishing the last VP8 frames to
// the SFU for tens of seconds (or the SFU continues echoing buffered video
// from the dead track). Server's vp8channel sees fresh frames with the
// locked epoch and never lets the peer-lock idle out — the smux session
// above thinks the client is alive, the ghost-peer release timer is
// disarmed (smuxOpened=true), and every new connect from the same phone
// is rejected as FOREIGN PEER forever.
//
// With KeepAlive on, server pings the client every 10 s and closes the
// session after 60 s of no response. That close cascades into
// Peer.closeSession → ResetPeerLock → next connect can latch a fresh epoch.
func smuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.KeepAliveDisabled = false
	cfg.MaxFrameSize = 32768
	cfg.MaxReceiveBuffer = 16 * 1024 * 1024
	cfg.MaxStreamBuffer = 1024 * 1024
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 60 * time.Second
	return cfg
}

// bringUpPeers spawns N peers in parallel. Returns nil if ALL peers
// become ready, or the first error if any fails. On any error, all
// other peers are also closed (no partial-ready operation).
func (s *Server) bringUpPeers(
	ctx context.Context,
	pconfigs []PeerConfig,
	cfg Config,
	cancel context.CancelFunc,
) error {
	errCh := make(chan error, len(pconfigs))
	for _, pc := range pconfigs {
		peer := NewPeer(pc.ClientID, pc.Key)
		peer.parent = s
		s.peersMu.Lock()
		s.peers = append(s.peers, peer)
		s.peersMu.Unlock()
		s.sessions.Register(peer)
		go func(p *Peer) {
			errCh <- s.startPeer(ctx, p, cfg, cancel)
		}(peer)
	}
	var firstErr error
	for i := 0; i < len(pconfigs); i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return firstErr
	}
	logger.Infof("Link connected (peers=%d)", len(pconfigs))
	return nil
}

// startPeer wires one Peer end-to-end: cipher → link → ICE/Connect →
// muxconn+smux.Server → serve loop. Closes peer.readyCh on success.
// Blocks until either the peer is ready or an error occurs.
func (s *Server) startPeer(
	ctx context.Context,
	p *Peer,
	cfg Config,
	cancel context.CancelFunc,
) error {
	if err := p.setupCipher(); err != nil {
		return fmt.Errorf("peer %s: %w", p.ClientID, err)
	}
	ln, err := link.New(ctx, cfg.Link, link.Config{
		Transport:       cfg.Transport,
		Carrier:         cfg.Carrier,
		RoomURL:         cfg.RoomURL,
		Engine:          cfg.Engine,
		URL:             cfg.URL,
		Token:           cfg.Token,
		DeviceID:        "",
		Name:            names.Generate(),
		OnData:          p.onData,
		DNSServer:       s.dnsServer,
		ProxyAddr:       s.socksProxyAddr,
		ProxyPort:       s.socksProxyPort,
		VideoWidth:      cfg.VideoWidth,
		VideoHeight:     cfg.VideoHeight,
		VideoFPS:        cfg.VideoFPS,
		VideoBitrate:    cfg.VideoBitrate,
		VideoHW:         cfg.VideoHW,
		VideoQRSize:     cfg.VideoQRSize,
		VideoQRRecovery: cfg.VideoQRRecovery,
		VideoCodec:      cfg.VideoCodec,
		VideoTileModule: cfg.VideoTileModule,
		VideoTileRS:     cfg.VideoTileRS,
		VP8FPS:          cfg.VP8FPS,
		VP8BatchSize:    cfg.VP8BatchSize,
		SEIFPS:          cfg.SEIFPS,
		SEIBatchSize:    cfg.SEIBatchSize,
		SEIFragmentSize: cfg.SEIFragmentSize,
		SEIAckTimeoutMS: cfg.SEIAckTimeoutMS,
	})
	if err != nil {
		return fmt.Errorf("peer %s: link.New: %w", p.ClientID, err)
	}
	p.mu.Lock()
	p.Link = ln
	p.mu.Unlock()

	ln.SetEndedCallback(func(reason string) {
		logger.Infof("peer %s: link reported conference end: %s", p.ClientID, reason)
		cancel() // ending conference cancels the whole server
	})
	ln.SetShouldReconnect(func() bool { return ctx.Err() == nil })
	ln.SetReconnectCallback(func() {
		if ctx.Err() != nil {
			return
		}
		p.handleReconnect()
	})

	logger.Infof("peer %s: connecting link via %s/%s/%s...", p.ClientID, cfg.Link, cfg.Transport, cfg.Carrier)
	if err := ln.Connect(ctx); err != nil {
		return fmt.Errorf("peer %s: link.Connect: %w", p.ClientID, err)
	}
	logger.Infof("peer %s: link connected", p.ClientID)

	p.installSession()
	close(p.readyCh)

	// Spawn per-peer goroutines (watcher + serve loop). They keep
	// s.wg alive until shutdown.
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		ln.WatchConnection(ctx)
	}()
	go func() {
		defer s.wg.Done()
		p.serve(ctx)
	}()
	return nil
}

func contextDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// shutdown closes every peer. Called when the server context cancels or
// when bringUpPeers errors out.
func (s *Server) shutdown() {
	s.peersMu.RLock()
	peers := append([]*Peer(nil), s.peers...)
	s.peersMu.RUnlock()
	for _, p := range peers {
		p.Close()
	}
}

// handleStream reads the connect-request JSON from the stream, then
// dispatches the proxied connection. sid is the originating peer's
// sessionID (or "" if called from a test without a peer); it's threaded
// through to onTraffic.
func (s *Server) handleStream(_ context.Context, stream *smux.Stream, sid string) {
	defer func() { _ = stream.Close() }()

	// Read the connect JSON. The client writes the whole JSON in one
	// stream.Write so it usually arrives intact; tolerate fragmentation
	// by reading incrementally up to a sane cap.
	const maxConnReq = 4096
	header := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	_ = stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	for {
		n, err := stream.Read(tmp)
		if n > 0 {
			header = append(header, tmp[:n]...)
			if req, ok := parseConnectRequest(header); ok {
				_ = stream.SetReadDeadline(time.Time{})
				s.dispatch(stream, req, sid)
				return
			}
		}
		if err != nil {
			return
		}
		if len(header) > maxConnReq {
			return
		}
	}
}

func parseConnectRequest(buf []byte) (ConnectRequest, bool) {
	var req ConnectRequest
	if err := json.Unmarshal(buf, &req); err != nil {
		return req, false
	}
	if req.Cmd != connectCommand {
		return req, false
	}
	return req, true
}

// defaultAuthHook admits every client and assigns a random session ID.
// Replace it via [Config.AuthHook] to plug in real authorization.
func defaultAuthHook(_ string, _ map[string]any) (string, error) {
	return uuid.NewString(), nil
}

func (s *Server) dispatch(stream *smux.Stream, req ConnectRequest, sid string) {
	addr := net.JoinHostPort(req.Addr, strconv.Itoa(req.Port))
	logger.Infof("sid=%d connect %s", stream.ID(), addr)

	dialStart := time.Now()
	conn, err := s.dial(req)
	dialElapsed := time.Since(dialStart)

	if err != nil {
		logger.Infof("sid=%d dial %s failed (%v): %v", stream.ID(), addr, dialElapsed, err)
		return
	}
	defer func() { _ = conn.Close() }()

	logger.Infof("sid=%d connected %s in %v", stream.ID(), addr, dialElapsed)

	if _, err := stream.Write([]byte{0x00}); err != nil {
		return
	}

	var bytesOut uint64
	done := make(chan struct{})
	go func() {
		n, _ := io.Copy(stream, conn)
		if n > 0 {
			bytesOut = uint64(n)
		}
		_ = stream.Close()
		close(done)
	}()
	in, _ := io.Copy(conn, stream)
	_ = conn.Close()
	<-done
	bytesIn := uint64(0)
	if in > 0 {
		bytesIn = uint64(in)
	}
	if s.onTraffic != nil {
		s.onTraffic(sid, addr, bytesIn, bytesOut)
	}
}

func (s *Server) dial(req ConnectRequest) (net.Conn, error) {
	addr := net.JoinHostPort(req.Addr, strconv.Itoa(req.Port))
	if s.socksProxyAddr == "" {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			Resolver:  s.resolver,
		}
		conn, err := dialer.Dial("tcp4", addr)
		if err != nil {
			return nil, fmt.Errorf("dial failed: %w", err)
		}
		return conn, nil
	}

	proxyAddr := net.JoinHostPort(s.socksProxyAddr, strconv.Itoa(s.socksProxyPort))
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.Dial("tcp4", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial proxy: %w", err)
	}

	if err := s.socks5Connect(conn, req.Addr, req.Port); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (s *Server) socks5Connect(conn net.Conn, targetAddr string, targetPort int) error {
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return fmt.Errorf("failed to write socks5 auth: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read socks5 auth resp: %w", err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		return ErrSocks5AuthFailed
	}

	addrLen := len(targetAddr)
	if addrLen > 255 {
		addrLen = 255
		targetAddr = targetAddr[:255]
	}

	req := make([]byte, 0, 7+addrLen)
	req = append(req, 5, 1, 0, 3, byte(addrLen))
	req = append(req, []byte(targetAddr)...)
	req = append(req, byte(targetPort>>8), byte(targetPort)) //nolint:gosec,lll // G115: bounded conversion verified by surrounding logic

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("failed to write socks5 connect req: %w", err)
	}

	resp = make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read socks5 connect resp: %w", err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		return fmt.Errorf("%w: %d", ErrSocks5ConnectFailed, resp[1])
	}

	return nil
}
