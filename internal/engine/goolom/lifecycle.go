package goolom

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/protect"
	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

// Connect starts the WebRTC connection process.
func (s *Session) Connect(ctx context.Context) error {
	s.closed.Store(false)
	s.resetMediaState()

	config := webrtc.Configuration{
		ICEServers:   []webrtc.ICEServer{{URLs: []string{"stun:stun.rtc.yandex.net:3478"}}},
		SDPSemantics: webrtc.SDPSemanticsUnifiedPlan,
	}

	if err := s.setupPeerConnections(config); err != nil {
		return err
	}

	keepAliveCh, sessionCloseCh := s.resetSession()
	var dcReady chan struct{}
	if s.onData != nil {
		var err error
		s.dc, err = s.pcPub.CreateDataChannel("olcrtc", nil)
		if err != nil {
			return fmt.Errorf("create dc: %w", err)
		}
		dcReady = make(chan struct{})
		s.setupDataChannelHandlers(dcReady, sessionCloseCh)
	}

	if err := s.dialWebSocket(); err != nil {
		return err
	}

	s.setupICEHandlers()
	s.startBackgroundGoroutines(ctx, keepAliveCh)

	if s.onData != nil {
		select {
		case <-dcReady:
			return nil
		case <-time.After(15 * time.Second):
			return ErrDataChannelTimeout
		case <-ctx.Done():
			return fmt.Errorf("connect context cancelled: %w", ctx.Err())
		}
	}

	return s.waitForMediaReady(ctx, 20*time.Second)
}

func (s *Session) waitForMediaReady(ctx context.Context, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-s.subscriberConn:
	case <-timer.C:
		return ErrSubscriberMediaTimeout
	case <-ctx.Done():
		return fmt.Errorf("connect context cancelled: %w", ctx.Err())
	}
	return nil
}

// sharedICEUDPMux is the single pre-protected UDP socket Pion uses for
// every ICE host candidate and STUN binding. Building it once and
// reusing across the publisher and subscriber peer connections keeps
// the NAT mapping stable, which is critical when the underlying
// network applies CGNAT/whitelist DPI (Tele2/МТС/...).
var (
	sharedICEUDPMux     ice.UDPMux
	sharedICEUDPMuxOnce sync.Once
	sharedICEUDPMuxErr  error
)

func getOrCreateICEUDPMux() (ice.UDPMux, error) {
	sharedICEUDPMuxOnce.Do(func() {
		lc := &net.ListenConfig{
			Control: func(_, _ string, c syscall.RawConn) error {
				p := protect.Protector
				if p == nil {
					return nil
				}
				var perr error
				if cerr := c.Control(func(fd uintptr) {
					if !p(int(fd)) {
						perr = fmt.Errorf("VpnService.protect failed for fd %d", fd)
					}
				}); cerr != nil {
					return cerr
				}
				return perr
			},
		}
		pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
		if err != nil {
			sharedICEUDPMuxErr = fmt.Errorf("listen protected UDP: %w", err)
			return
		}
		sharedICEUDPMux = webrtc.NewICEUDPMux(nil, pc.(*net.UDPConn))
	})
	return sharedICEUDPMux, sharedICEUDPMuxErr
}

func (s *Session) setupPeerConnections(config webrtc.Configuration) error {
	settingEngine := webrtc.SettingEngine{}
	if protect.Protector != nil {
		settingEngine.SetICEProxyDialer(protect.NewProxyDialer())

		// Pin all ICE/STUN UDP through a single pre-protected socket.
		// On Android, otherwise Pion binds 0.0.0.0 sockets that get
		// trapped in the app's own VpnService TUN, and NAT mapping
		// fragments across multiple host candidates so the remote SFU
		// can't pick one to talk back to.
		if mux, err := getOrCreateICEUDPMux(); err == nil && mux != nil {
			settingEngine.SetICEUDPMux(mux)
		} else if err != nil {
			logger.Debugf("ice udp mux unavailable: %v (continuing without it)", err)
		}

		// Exclude TUN-like interfaces so Pion doesn't gather useless
		// 10.10.10.1 host candidates that loop through our own VPN.
		settingEngine.SetInterfaceFilter(func(name string) bool {
			n := strings.ToLower(name)
			return !strings.HasPrefix(n, "tun") &&
				!strings.HasPrefix(n, "ppp") &&
				!strings.HasPrefix(n, "tap")
		})
	}
	settingEngine.LoggerFactory = logger.NewPionLoggerFactory()
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))

	var err error
	s.pcSub, err = api.NewPeerConnection(config)
	if err != nil {
		return fmt.Errorf("new sub pc: %w", err)
	}
	s.pcSub.OnConnectionStateChange(s.onSubscriberConnectionStateChange)
	s.pcSub.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		logger.Infof("trackdiag: SUB OnTrack kind=%s codec=%s ssrc=%d stream=%s track=%s",
			track.Kind(), track.Codec().MimeType, track.SSRC(), track.StreamID(), track.ID())
		if track.Kind() != webrtc.RTPCodecTypeVideo {
			return
		}
		if cb := s.videoTrackHandler(); cb != nil {
			cb(track, receiver)
		} else {
			logger.Infof("trackdiag: WARN no videoTrackHandler set — track=%s dropped", track.ID())
		}
	})

	s.pcPub, err = api.NewPeerConnection(config)
	if err != nil {
		return fmt.Errorf("new pub pc: %w", err)
	}
	s.pcPub.OnConnectionStateChange(s.onPublisherConnectionStateChange)

	if err := s.attachPendingVideoTracks(); err != nil {
		return err
	}
	return nil
}

func (s *Session) dialWebSocket() error {
	wsDialer := websocket.Dialer{
		NetDialContext:   protect.DialContext,
		HandshakeTimeout: wsHandshakeTimeout,
	}
	ws, resp, err := wsDialer.Dial(s.mediaServerURL, nil)
	if err != nil {
		return fmt.Errorf("dial ws: %w", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	s.ws = ws

	ws.SetPongHandler(func(string) error {
		_ = ws.SetReadDeadline(time.Now().Add(wsReadTimeout))
		return nil
	})
	_ = ws.SetReadDeadline(time.Now().Add(wsReadTimeout))
	return nil
}

func (s *Session) startBackgroundGoroutines(ctx context.Context, keepAliveCh chan struct{}) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.keepAlive(keepAliveCh)
	}()

	_ = s.sendHello()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.handleSignaling(ctx)
	}()
}

func (s *Session) onConnectionStateChange(state webrtc.PeerConnectionState) {
	if !s.closed.Load() && state == webrtc.PeerConnectionStateFailed {
		s.queueReconnect()
	}
}

func (s *Session) onSubscriberConnectionStateChange(state webrtc.PeerConnectionState) {
	logger.Debugf("goolom subscriber state: %s", state.String())
	switch state {
	case webrtc.PeerConnectionStateConnected:
		s.subscriberReady.Store(true)
		closeSignal(s.subscriberConn)
	case webrtc.PeerConnectionStateDisconnected,
		webrtc.PeerConnectionStateFailed,
		webrtc.PeerConnectionStateClosed:
		s.subscriberReady.Store(false)
	case webrtc.PeerConnectionStateUnknown,
		webrtc.PeerConnectionStateNew,
		webrtc.PeerConnectionStateConnecting:
	}
	s.onConnectionStateChange(state)
}

func (s *Session) onPublisherConnectionStateChange(state webrtc.PeerConnectionState) {
	logger.Debugf("goolom publisher state: %s", state.String())
	switch state {
	case webrtc.PeerConnectionStateConnected:
		s.publisherReady.Store(true)
		closeSignal(s.publisherConn)
	case webrtc.PeerConnectionStateDisconnected,
		webrtc.PeerConnectionStateFailed,
		webrtc.PeerConnectionStateClosed:
		s.publisherReady.Store(false)
	case webrtc.PeerConnectionStateUnknown,
		webrtc.PeerConnectionStateNew,
		webrtc.PeerConnectionStateConnecting:
	}
	s.onConnectionStateChange(state)
}

// Close terminates the session and releases resources.
func (s *Session) Close() error {
	alreadyClosing := s.closed.Swap(true)
	s.sendQueueClosed.Store(true)

	if !alreadyClosing {
		leaveUID := uuid.New().String()
		leaveAck := s.registerAckWaiter(leaveUID)
		if s.sendLeave(leaveUID) {
			_ = s.waitForAck(leaveUID, leaveAck, 1500*time.Millisecond)
		} else {
			s.removeAckWaiter(leaveUID)
		}
	}

	closeSignal(s.closeCh)
	s.stopSession()

	if s.dc != nil {
		_ = s.dc.Close()
	}
	if s.pcPub != nil {
		_ = s.pcPub.Close()
	}
	if s.pcSub != nil {
		_ = s.pcSub.Close()
	}
	if s.ws != nil {
		s.wsMu.Lock()
		_ = s.ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second))
		_ = s.ws.Close()
		s.wsMu.Unlock()
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	return nil
}

// WatchConnection monitors the connection lifecycle and reconnects as needed.
func (s *Session) WatchConnection(ctx context.Context) {
	const maxReconnects = 10
	const reconnectWindow = 5 * time.Minute

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closeCh:
			return
		case <-s.reconnectCh:
			if s.handleReconnectAttempt(ctx, maxReconnects, reconnectWindow) {
				return
			}
		}
	}
}

func (s *Session) handleReconnectAttempt(ctx context.Context, maxReconnects int, reconnectWindow time.Duration) bool {
	if time.Since(s.lastReconnect) > reconnectWindow {
		s.reconnectCount = 0
	}
	s.reconnectCount++
	s.lastReconnect = time.Now()

	if s.reconnectCount > maxReconnects {
		s.signalEnded("reconnect limit reached")
		return true
	}

	backoff := time.Duration(s.reconnectCount) * 2 * time.Second
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	return s.retryReconnect(ctx, backoff)
}

func (s *Session) retryReconnect(ctx context.Context, backoff time.Duration) bool {
	for {
		if err := s.reconnect(ctx); err != nil {
			logger.Debugf("reconnect failed: %v", err)
			select {
			case <-ctx.Done():
				return true
			case <-s.closeCh:
				return true
			case <-time.After(backoff):
				continue
			}
		}
		break
	}
	return false
}

func (s *Session) reconnect(ctx context.Context) error {
	s.reconnecting.Store(true)
	defer s.reconnecting.Store(false)

	s.sendLeave(uuid.New().String())
	time.Sleep(500 * time.Millisecond)
	s.stopSession()

	if s.dc != nil {
		_ = s.dc.Close()
	}
	if s.pcPub != nil {
		_ = s.pcPub.Close()
	}
	if s.pcSub != nil {
		_ = s.pcSub.Close()
	}
	if s.ws != nil {
		s.wsMu.Lock()
		_ = s.ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second))
		_ = s.ws.Close()
		s.wsMu.Unlock()
	}

	if s.onReconnect != nil {
		s.onReconnect(nil)
	}

	time.Sleep(3 * time.Second)
	if s.refresh == nil {
		return ErrNoRefresh
	}
	creds, err := s.refresh(ctx)
	if err != nil {
		return fmt.Errorf("reconnect refresh: %w", err)
	}
	s.applyRefreshedCredentials(creds)

	if err := s.Connect(ctx); err != nil {
		return err
	}
	if s.onReconnect != nil {
		s.onReconnect(s.dc)
	}
	s.drainReconnectQueue()
	return nil
}

func (s *Session) applyRefreshedCredentials(creds engine.Credentials) {
	if creds.URL != "" {
		s.mediaServerURL = creds.URL
	}
	if creds.Token != "" {
		s.peerID = creds.Token
	}
	if creds.Extra == nil {
		return
	}
	if v := creds.Extra[credentialKeyRoomID]; v != "" {
		s.roomID = v
	}
	if v := creds.Extra[credentialKeyCredentials]; v != "" {
		s.credentials = v
	}
	if v := creds.Extra[credentialKeyRoomURL]; v != "" {
		s.roomURL = v
	}
	if v := creds.Extra[credentialKeyTelemetryReferer]; v != "" {
		s.telemetryReferer = v
	}
}

func (s *Session) drainReconnectQueue() {
	for {
		select {
		case <-s.reconnectCh:
		default:
			return
		}
	}
}

func (s *Session) queueReconnect() {
	if s.closed.Load() || s.reconnecting.Load() {
		return
	}
	if s.shouldReconnect != nil && !s.shouldReconnect() {
		return
	}
	select {
	case s.reconnectCh <- struct{}{}:
	default:
	}
}

func (s *Session) stopSession() {
	s.stopTelemetry()
	s.sessionMu.Lock()
	closeSignal(s.keepAliveCh)
	closeSignal(s.sessionCloseCh)
	s.sessionMu.Unlock()
}

func (s *Session) resetSession() (chan struct{}, chan struct{}) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	s.keepAliveCh = make(chan struct{})
	s.sessionCloseCh = make(chan struct{})
	return s.keepAliveCh, s.sessionCloseCh
}

func (s *Session) resetMediaState() {
	s.subscriberReady.Store(false)
	s.publisherReady.Store(false)
	s.subscriberConn = make(chan struct{})
	s.publisherConn = make(chan struct{})
}

func (s *Session) signalEnded(reason string) {
	s.closed.Store(true)
	s.stopTelemetry()
	if s.onEnded != nil {
		s.onEnded(reason)
	}
}
