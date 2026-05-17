package server

import (
	"sync"
	"testing"
)

func TestSessionsRegisterFind(t *testing.T) {
	reg := NewSessions()
	p := NewPeer("c1", []byte("k1"))
	reg.Register(p)
	got, ok := reg.Find("c1")
	if !ok || got != p {
		t.Fatalf("find failed: %v %v", got, ok)
	}
}

func TestSessionsFindUnknown(t *testing.T) {
	reg := NewSessions()
	if _, ok := reg.Find("absent"); ok {
		t.Fatalf("expected false")
	}
}

func TestSessionsUnregister(t *testing.T) {
	reg := NewSessions()
	p := NewPeer("c1", []byte("k"))
	reg.Register(p)
	reg.Unregister("c1")
	if _, ok := reg.Find("c1"); ok {
		t.Fatalf("still present")
	}
}

func TestSessionsConcurrent(t *testing.T) {
	reg := NewSessions()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := string(rune('a' + i%26))
			reg.Register(NewPeer(id, nil))
			_, _ = reg.Find(id)
			reg.Unregister(id)
		}(i)
	}
	wg.Wait()
}

func TestSessionsUnregisterOnPeerClose(t *testing.T) {
	s := &Server{sessions: NewSessions()}
	p := NewPeer("client-99", []byte("01234567890123456789012345678901"))
	p.parent = s
	s.sessions.Register(p)
	if s.sessions.Count() != 1 {
		t.Fatalf("expected 1 registered, got %d", s.sessions.Count())
	}
	p.Close()
	if s.sessions.Count() != 0 {
		t.Fatalf("Peer.Close should unregister; got count=%d", s.sessions.Count())
	}
}
