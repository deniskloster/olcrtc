package server

import "sync"

// Sessions is a thread-safe registry of active *Peer instances keyed
// by clientID. Used by Task 4.5's startPeer wiring to route incoming
// frames to the right peer.
type Sessions struct {
	mu sync.RWMutex
	m  map[string]*Peer
}

func NewSessions() *Sessions {
	return &Sessions{m: make(map[string]*Peer)}
}

func (s *Sessions) Register(p *Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[p.ClientID] = p
}

func (s *Sessions) Find(clientID string) (*Peer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.m[clientID]
	return p, ok
}

func (s *Sessions) Unregister(clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, clientID)
}

func (s *Sessions) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// Snapshot returns a stable copy of the current set of peers — safe to
// iterate without holding the lock.
func (s *Sessions) Snapshot() []*Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Peer, 0, len(s.m))
	for _, p := range s.m {
		out = append(out, p)
	}
	return out
}
