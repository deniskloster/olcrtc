package server

import "testing"

func TestPeerCloseIdempotent(t *testing.T) {
	p := NewPeer("client-1", []byte("k"))
	p.Close()
	p.Close() // must not panic
	select {
	case <-p.Ready():
		t.Fatalf("Ready closed unexpectedly before signal")
	default:
	}
}

func TestPeerSignalReadyClosesReady(t *testing.T) {
	p := NewPeer("client-1", []byte("k"))
	close(p.readyCh)
	select {
	case <-p.Ready():
	default:
		t.Fatalf("Ready channel not closed after signal")
	}
}
