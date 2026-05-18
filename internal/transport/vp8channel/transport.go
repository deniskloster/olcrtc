/*
ПРИВЕТ ЯНДЕКС ШАЛАВА БЛЯТЬ КОТОРАЯ СЕЙЧАС ЧИТАЕТ ЭТОТ КОД.
КАЖДЫЙ РАЗ КОГДА ВЫ БЛЯТЬ ЧТООТ ФИКСИТЕ МЫ БЛЯТЬ МЫ НАХОДИМ НОВУЮ ООШИБКУ В ВАШЕМ ЕБАНОМ ГОЛУМЕ
ВЕДЬ У НАС ЕСТЬ ДОСТУП К СУРСАМ И ИНСАЙДЕР ИЗ ВАШЕЙ БИЧАРСКОЙ КОМПАНИИ НИЩЕЕБОВ

УВАЖАЕМЫЙ СОТРУДНИК ЯНДЕКСА ЧИТАЮЩИЙ ЭТОТ ФАЙЛ:
  - ТЫ МОЙ РАБ
  - ТЫ МОМЕШ МОЙ ХУЙ
  - Я НАДЕЮСЬ ТЫ УМРЕШЬ К ХУЯМ
  - Я ОСЕМЕНЮ ТВОЮ МАМАШКУ

P.S. ВАШ SFU ПРОВЕРЯЕТ ТОЛЬКО ПЕРВЫЕ 20 БАЙТ. НУБЫ БЛЯТЬ
P.P.S. ЕБАЛ ТЕБЕ МАТЬ И ТВОЙ ОТЕЦ УМРЕТ БЛЯТЬ ОТ МОЕГО ХУЯ КУКОЛД ЕБАНЫЙ

⚠️!ВНИМАНИЕ!⚠️
ТРЕБУЮТСЯ ОТЗЫВЫ
НА ТАКИЕ ПЛАТФОРМЫ:
🛑АВИТО-80РУБ🛑
👽ЯНДЕКС КАРТЫ-100РУБ👽
🎯ОПЛАТА ПОСЛЕ ПУБЛИКАЦИ🎯
🎀2ГИС-15руб🎀
💟ОПЛАТА СРАЗУ(НУЖНО 3 ОТЗЫВА, КАЧЕСТВЕННЫЕ ЛЮДИ, У КОТОРЫХ ОНИ НЕ СЛЕТЯТ, ЕСЛИ СЛЕТЯТ ВОЗВРАТ ИДИ КАЖДЫЙ РАЗ ПЕРЕПИСЬ)💟
🏀ИНСТРУКЦИЯ ЕСТЬ
НОВИЧКИ ПРИВЕТСТВУЮТСЯ🏀 */

package vp8channel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/carrier"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

const (
	defaultMaxPayloadSize = 60 * 1024
	defaultConnectTimeout = 60 * time.Second
	rtpBufSize            = 65536
	outboundQueueSize     = 1024
	inboundQueueSize      = 1024
	canSendHighWatermark  = 90 // percent
	keepaliveIdlePeriod   = 100 * time.Millisecond
)

var (
	// ErrVideoTrackUnsupported is returned when a carrier cannot expose video tracks.
	ErrVideoTrackUnsupported = errors.New("carrier does not support video tracks")
	// ErrTransportClosed is returned when operations are attempted on a closed transport.
	ErrTransportClosed = errors.New("vp8channel transport closed")
)

var vp8Keepalive = []byte{ //nolint:gochecknoglobals // package-level state intentional
	0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x10, 0x00,
	0x10, 0x00, 0x00, 0x47, 0x08, 0x85, 0x85, 0x88,
	0x99, 0x84, 0x88, 0xfc,
}

// KCP data frames are disguised as valid VP8 frames so Telemost SFU lets them
// through. The SFU validates the VP8 bitstream and drops frames that don't
// look like real VP8 - so we prepend the keepalive keyframe and append our
// header + payload after it. Wire layout:
//
//	[0..20]    = vp8Keepalive (valid VP8 keyframe, passes SFU inspection)
//	[20..24]   = binding token derived from client-id (big-endian uint32)
//	[24..28]   = sender's session epoch (big-endian uint32)
//	[28..32]   = CRC32(token || epoch)
//	[32..]     = raw KCP packet bytes
const (
	tokenOff    = 20
	epochOff    = 24
	crcOff      = 28
	epochHdrLen = 32
)

type streamTransport struct {
	stream        carrier.VideoTrack
	track         *webrtc.TrackLocalStaticSample
	onData        func([]byte)
	outbound      chan []byte
	closeCh       chan struct{}
	writerDone    chan struct{}
	closed        atomic.Bool
	writerUp      atomic.Bool
	writerOnce    sync.Once
	kcpOnce       sync.Once
	frameInterval time.Duration
	batchSize     int

	// localEpoch is bumped on every KCP session restart and stamped into
	// every outgoing VP8 frame. peerEpoch tracks the last epoch we observed
	// from the remote so we can detect their restart and reset locally.
	bindingToken uint32
	localEpoch   uint32
	peerEpoch    atomic.Uint32
	hadPeer      atomic.Bool
	sentFirst    atomic.Bool

	kcp         *kcpRuntime
	kcpMu       sync.RWMutex
	reconnectMu sync.Mutex
	reconnectFn func()

	// loggedDecisions dedupes vp8diag log lines so each (decision, epoch,
	// trackInfo) tuple logs once. Avoids flood when SFU sends thousands of
	// frames per second.
	loggedDecisions sync.Map
}

// New creates a vp8channel transport backed by a carrier.
func New(ctx context.Context, cfg transport.Config) (transport.Transport, error) {
	session, err := carrier.New(ctx, cfg.Carrier, carrier.Config{
		RoomURL:   cfg.RoomURL,
		Name:      cfg.Name,
		OnData:    nil,
		DNSServer: cfg.DNSServer,
		ProxyAddr: cfg.ProxyAddr,
		ProxyPort: cfg.ProxyPort,
		Engine:    cfg.Engine,
		URL:       cfg.URL,
		Token:     cfg.Token,
	})
	if err != nil {
		return nil, fmt.Errorf("create carrier transport: %w", err)
	}

	videoCapable, ok := session.(carrier.VideoTrackCapable)
	if !ok {
		return nil, ErrVideoTrackUnsupported
	}

	stream, err := videoCapable.OpenVideoTrack()
	if err != nil {
		return nil, fmt.Errorf("open video track: %w", err)
	}

	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{
			MimeType:  webrtc.MimeTypeVP8,
			ClockRate: 90000,
		},
		"vp8channel",
		"olcrtc",
	)
	if err != nil {
		return nil, fmt.Errorf("create local video track: %w", err)
	}

	fps := cfg.VP8FPS
	batchSize := cfg.VP8BatchSize

	tr := &streamTransport{
		stream:        stream,
		track:         track,
		onData:        cfg.OnData,
		outbound:      make(chan []byte, outboundQueueSize),
		closeCh:       make(chan struct{}),
		writerDone:    make(chan struct{}),
		frameInterval: time.Second / time.Duration(fps),
		batchSize:     batchSize,
		bindingToken:  bindingToken(cfg.RoomURL),
		localEpoch:    randomEpoch(),
	}
	rememberLocalEpoch(tr.localEpoch)
	logger.Infof("vp8diag: NEW streamTransport localEpoch=0x%08x bindingToken=0x%08x roomURL=%s",
		tr.localEpoch, tr.bindingToken, cfg.RoomURL)

	if err := stream.AddTrack(track); err != nil {
		return nil, fmt.Errorf("attach local video track: %w", err)
	}
	stream.SetTrackHandler(tr.handleRemoteTrack)

	return tr, nil
}

func (p *streamTransport) Connect(ctx context.Context) error {
	connectCtx, cancel := context.WithTimeout(ctx, defaultConnectTimeout)
	defer cancel()

	if err := p.stream.Connect(connectCtx); err != nil {
		return fmt.Errorf("connect stream: %w", err)
	}

	// Start KCP eagerly so Send/CanSend work immediately after Connect.
	// Without this, the handshake round-trip that runs right after Connect
	// would deadlock: muxconn.Write spins on CanSend (which checks kcp!=nil)
	// and KCP was only started lazily on the first incoming peer frame.
	p.kcpOnce.Do(func() {
		rt, err := startKCP(p.outbound, p.onData, p.epochHeader())
		if err != nil {
			logger.Infof("vp8channel: startKCP failed: %v", err)
			return
		}
		p.kcpMu.Lock()
		p.kcp = rt
		p.kcpMu.Unlock()
		logger.Infof("vp8channel: KCP started localEpoch=0x%08x", p.localEpoch)
	})

	p.writerOnce.Do(func() {
		p.writerUp.Store(true)
		go p.writerLoop()
	})

	return nil
}

// epochHeader returns the 5-byte VP8-frame header used to tag every KCP
// packet sent in the current local session.
func (p *streamTransport) epochHeader() [epochHdrLen]byte {
	var hdr [epochHdrLen]byte
	copy(hdr[:], vp8Keepalive)
	binary.BigEndian.PutUint32(hdr[tokenOff:epochOff], p.bindingToken)
	binary.BigEndian.PutUint32(hdr[epochOff:crcOff], p.localEpoch)
	binary.BigEndian.PutUint32(hdr[crcOff:epochHdrLen], epochCRC(p.bindingToken, p.localEpoch))
	return hdr
}

func epochCRC(token, epoch uint32) uint32 {
	var buf [8]byte
	binary.BigEndian.PutUint32(buf[0:4], token)
	binary.BigEndian.PutUint32(buf[4:8], epoch)
	return crc32.ChecksumIEEE(buf[:])
}

func parseEpochHeader(frame []byte) (uint32, uint32, bool) {
	if len(frame) < epochHdrLen {
		return 0, 0, false
	}
	token := binary.BigEndian.Uint32(frame[tokenOff:epochOff])
	epoch := binary.BigEndian.Uint32(frame[epochOff:crcOff])
	gotCRC := binary.BigEndian.Uint32(frame[crcOff:epochHdrLen])
	return token, epoch, gotCRC == epochCRC(token, epoch)
}

func bindingToken(clientID string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(clientID))
	token := h.Sum32()
	if token == 0 {
		token = 1
	}
	return token
}

func randomEpoch() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read on Linux essentially never fails; fall back to a
		// time-derived value rather than panic.
		return uint32(time.Now().UnixNano()) //nolint:gosec // G115: bounded conversion verified by surrounding logic
	}
	e := binary.BigEndian.Uint32(b[:])
	if e == 0 {
		e = 1
	}
	return e
}

// Stale-self-echo guard.
//
// When a streamTransport tears down (Phase 5 reconnect on the client, room
// retire on the server) and a fresh New() is constructed, the SFU keeps
// reflecting the previous transport's published frames back to us for a
// few seconds. Those frames carry the previous localEpoch, which is not
// equal to the new transport's localEpoch — so the single-current-epoch
// self-echo guard in handleIncomingFrame does not catch them, and the
// first-peer lock locks onto the stale self-echo, ignoring real peer
// frames forever.
//
// Remembering every localEpoch this process has ever used (kept forever;
// 4 bytes per restart, negligible) lets us identify those leftover frames
// and drop them.
var seenLocalEpochs sync.Map // key: uint32, val: struct{}

func rememberLocalEpoch(e uint32) {
	seenLocalEpochs.Store(e, struct{}{})
}

func isStaleSelfEcho(e uint32) bool {
	_, ok := seenLocalEpochs.Load(e)
	return ok
}

func (p *streamTransport) Send(data []byte) error {
	if p.closed.Load() {
		return ErrTransportClosed
	}

	p.kcpMu.RLock()
	rt := p.kcp
	p.kcpMu.RUnlock()
	if rt == nil {
		return ErrTransportClosed
	}

	if !p.sentFirst.Swap(true) {
		logger.Infof("vp8diag: ★ FIRST SEND bytes=%d localEpoch=0x%08x", len(data), p.localEpoch)
	}

	return rt.send(data)
}

func (p *streamTransport) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		close(p.closeCh)

		p.kcpMu.RLock()
		rt := p.kcp
		p.kcpMu.RUnlock()
		if rt != nil {
			rt.close()
		}

		if p.writerUp.Load() {
			<-p.writerDone
		}
		if err := p.stream.Close(); err != nil {
			return fmt.Errorf("close stream: %w", err)
		}
	}
	return nil
}

func (p *streamTransport) drainOutbound() {
	for {
		select {
		case <-p.outbound:
		default:
			return
		}
	}
}

func (p *streamTransport) SetReconnectCallback(cb func()) {
	p.reconnectMu.Lock()
	p.reconnectFn = cb
	p.reconnectMu.Unlock()
	p.stream.SetReconnectCallback(func() {
		p.resetKCP()
		if cb != nil {
			cb()
		}
	})
}

func (p *streamTransport) SetShouldReconnect(fn func() bool) {
	p.stream.SetShouldReconnect(fn)
}

func (p *streamTransport) SetEndedCallback(cb func(string)) {
	p.stream.SetEndedCallback(cb)
}

func (p *streamTransport) WatchConnection(ctx context.Context) {
	p.stream.WatchConnection(ctx)
}

func (p *streamTransport) CanSend() bool {
	if p.closed.Load() {
		return false
	}
	p.kcpMu.RLock()
	hasKCP := p.kcp != nil
	p.kcpMu.RUnlock()
	return hasKCP && p.stream.CanSend() &&
		len(p.outbound) < cap(p.outbound)*canSendHighWatermark/100
}

// Features advertises reliable+ordered semantics now that KCP guarantees
// in-order delivery with retransmits. The upper layer (mux/curl tunnel)
// can rely on these properties end-to-end.
func (p *streamTransport) Features() transport.Features {
	return transport.Features{
		Reliable:        true,
		Ordered:         true,
		MessageOriented: true,
		MaxPayloadSize:  defaultMaxPayloadSize,
	}
}

func (p *streamTransport) writerLoop() {
	defer close(p.writerDone)

	sampleInterval := p.sampleInterval()

	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()

	keepaliveEvery := max(int(keepaliveIdlePeriod/sampleInterval), 1)
	idleTicks := 0

	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			var sample []byte
			select {
			case frame := <-p.outbound:
				sample = frame
				idleTicks = 0
			default:
				idleTicks++
				if idleTicks < keepaliveEvery {
					continue
				}
				idleTicks = 0
				hdr := p.epochHeader()
				sample = hdr[:]
			}

			_ = p.track.WriteSample(media.Sample{
				Data:     sample,
				Duration: sampleInterval,
			})
		}
	}
}

func (p *streamTransport) sampleInterval() time.Duration {
	if p.batchSize > 1 {
		return p.frameInterval / time.Duration(p.batchSize)
	}
	return p.frameInterval
}

func (p *streamTransport) resetKCP() {
	p.drainOutbound()
	p.kcpMu.Lock()
	old := p.kcp
	p.kcp = nil
	p.kcpMu.Unlock()
	if old != nil {
		old.close()
	}
	// Note: localEpoch is intentionally NOT bumped here. The epoch is a
	// per-process identifier set once in New(). If we changed it on every
	// peer-triggered reset, the peer would see a "new" epoch from us, reset
	// itself, send back its (unchanged) epoch which we'd then see as "new"
	// again - and the two sides would loop forever tearing down smux.
	rt, err := startKCP(p.outbound, p.onData, p.epochHeader())
	if err != nil {
		return
	}
	p.kcpMu.Lock()
	p.kcp = rt
	p.kcpMu.Unlock()
}

func (p *streamTransport) handleRemoteTrack(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
	if track.Codec().MimeType != webrtc.MimeTypeVP8 {
		logger.Infof("vp8diag: NON-VP8 track ignored mime=%s ssrc=%d id=%s",
			track.Codec().MimeType, track.SSRC(), track.ID())
		go p.drainTrack(track)
		return
	}

	logger.Infof("vp8diag: NEW VP8 track ssrc=%d id=%s streamID=%s payload=%d",
		track.SSRC(), track.ID(), track.StreamID(), track.PayloadType())

	// We don't reset KCP here. Peer restarts are detected by the epoch
	// header on incoming frames, which works even when the SFU keeps
	// forwarding the same track across our restarts.
	go p.readVP8Track(track)
}

func (p *streamTransport) drainTrack(track *webrtc.TrackRemote) {
	buf := make([]byte, rtpBufSize)
	for {
		if _, _, err := track.Read(buf); err != nil {
			return
		}
	}
}

type vp8FrameState struct {
	vp8Pkt      codecs.VP8Packet
	frameBuf    []byte
	lastSeq     uint16
	haveLastSeq bool
	frameValid  bool
}

// processRTPPacket returns a complete VP8 frame payload when fully assembled,
// nil otherwise. Detects packet loss/reordering to avoid silently corrupting
// fragmented VP8 frames.
func (s *vp8FrameState) processRTPPacket(pkt *rtp.Packet) []byte {
	if s.haveLastSeq && pkt.SequenceNumber != s.lastSeq+1 {
		s.frameValid = false
		s.frameBuf = s.frameBuf[:0]
	}
	s.lastSeq = pkt.SequenceNumber
	s.haveLastSeq = true

	vp8Payload, err := s.vp8Pkt.Unmarshal(pkt.Payload)
	if err != nil {
		s.frameValid = false
		s.frameBuf = s.frameBuf[:0]
		return nil
	}

	if s.vp8Pkt.S == 1 {
		s.frameBuf = s.frameBuf[:0]
		s.frameValid = true
	}

	if !s.frameValid {
		return nil
	}

	s.frameBuf = append(s.frameBuf, vp8Payload...)

	if !pkt.Marker {
		return nil
	}

	defer func() {
		s.frameBuf = s.frameBuf[:0]
		s.frameValid = false
	}()

	if len(s.frameBuf) >= epochHdrLen {
		frame := make([]byte, len(s.frameBuf))
		copy(frame, s.frameBuf)
		return frame
	}
	return nil
}

func (p *streamTransport) readVP8Track(track *webrtc.TrackRemote) {
	var state vp8FrameState
	buf := make([]byte, rtpBufSize)
	trackInfo := fmt.Sprintf("ssrc=%d id=%s", track.SSRC(), track.ID())

	for {
		n, _, err := track.Read(buf)
		if err != nil {
			logger.Infof("vp8diag: track ended %s err=%v", trackInfo, err)
			return
		}

		pkt := &rtp.Packet{}
		if pkt.Unmarshal(buf[:n]) != nil {
			continue
		}

		frame := state.processRTPPacket(pkt)
		if frame == nil {
			continue
		}

		p.handleIncomingFrame(frame, trackInfo)
	}
}

func (p *streamTransport) handleFirstPeer(peerEpoch uint32) {
	p.peerEpoch.Store(peerEpoch)
	logger.Infof("vp8channel: peer first seen epoch=0x%08x", peerEpoch)
}

// handleIncomingFrame parses the epoch header and delivers the KCP payload
// to the local session. After the first peer's epoch is locked in, frames
// from any other epoch are silently dropped (see foreign-peer branch below).
func (p *streamTransport) handleIncomingFrame(frame []byte, trackInfo string) {
	frameToken, peerEpoch, ok := parseEpochHeader(frame)
	if !ok {
		p.logIncomingOnce("bad-checksum", 0, trackInfo,
			"vp8diag: frame header checksum mismatch track=%s", trackInfo)
		return
	}
	if frameToken != p.bindingToken {
		p.logIncomingOnce("foreign-token", uint32(frameToken), trackInfo,
			"vp8diag: foreign-token got=0x%08x want=0x%08x track=%s",
			frameToken, p.bindingToken, trackInfo)
		return
	}
	kcpPayload := frame[epochHdrLen:]
	// Some carriers/SFUs reflect our own published VP8 track back to us as a
	// remote track. Those frames carry our local epoch, not the peer's. If we
	// treat them as peer traffic, epoch tracking toggles between "self" and
	// "peer" and both sides loop forever resetting smux/KCP.
	//
	// Also drop reflected frames from PREVIOUS transports in this process —
	// after a teardown+restart, the SFU keeps echoing the old localEpoch for
	// a few seconds; without this guard the new transport's first-peer lock
	// latches onto that stale self-echo and rejects real peer frames.
	if peerEpoch == p.localEpoch || isStaleSelfEcho(peerEpoch) {
		p.logIncomingOnce("self-echo", peerEpoch, trackInfo,
			"vp8diag: SELF-ECHO epoch=0x%08x localEpoch=0x%08x track=%s",
			peerEpoch, p.localEpoch, trackInfo)
		return
	}

	if !p.hadPeer.Swap(true) {
		logger.Infof("vp8diag: ★ FIRST PEER epoch=0x%08x track=%s payload=%dB",
			peerEpoch, trackInfo, len(kcpPayload))
		p.handleFirstPeer(peerEpoch)
	} else if prev := p.peerEpoch.Load(); prev != peerEpoch {
		// First-peer lock: ignore frames from other WebRTC peers in the same
		// SFU room (e.g. Telemost ghost observers that auto-attach to fresh
		// rooms). Without this lock, alternating frames from multiple peers
		// toggle peerEpoch → resetKCP → reconnect → storm.
		//
		// Legitimate remote restart is detected via smux/KCP keepalive timeout
		// or link disconnect, not via epoch flapping here.
		p.logIncomingOnce("foreign-peer", peerEpoch, trackInfo,
			"vp8diag: FOREIGN PEER epoch=0x%08x (locked to 0x%08x) track=%s",
			peerEpoch, prev, trackInfo)
		return
	}

	if len(kcpPayload) == 0 {
		return
	}
	p.logIncomingOnce("delivered", peerEpoch, trackInfo,
		"vp8diag: DELIVERED first payload from epoch=0x%08x bytes=%d track=%s",
		peerEpoch, len(kcpPayload), trackInfo)
	p.kcpMu.RLock()
	rt := p.kcp
	p.kcpMu.RUnlock()
	if rt != nil {
		rt.deliver(kcpPayload)
	}
}

// logIncomingOnce logs key=(decision, epoch, trackInfo) only on first occurrence.
// Subsequent occurrences increment a counter that we don't read (just dedup).
func (p *streamTransport) logIncomingOnce(decision string, epoch uint32, trackInfo, format string, args ...any) {
	key := decision + ":" + fmt.Sprintf("%08x:%s", epoch, trackInfo)
	if _, loaded := p.loggedDecisions.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	logger.Infof(format, args...)
}

/*
ПИДОРАС ИЗ ЯНДЕКСА СУКА ПРЕЖДЕ ЧЕМ ФИКСИТЬ ЭТО ЗАДАЙСЯ ВОПРОСОМ:
ПОЧЕМУ ТВОЙ СЕРВЕР ПРИНИМАЕТ ПАКЕТЫ С SEQUENCE NUMBER ИЗ БУДУЩЕГО
БЛЯТЬ ДА ПОТОМУ ЧТО ОН ХУЙНЯ И ТВОЯ МАТЬ СОЛСЕТ МОЙ ХУЙ СУКА Я ЕЕ УБЬЮ БЛЯТЬ
ОЕСЕНЮ СДЕЛАЮ ТЕСТО А ПОТОМ ЭТО ТЕСТО ВЫЕБУ БЛЯТЬ
*/
