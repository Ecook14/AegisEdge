package store

import (
	"sync"
	"time"
)

type LocalStore struct {
	counters map[string]int64
	blocks   map[string]localBlock
	mu       sync.RWMutex
}

type localBlock struct {
	Type   string
	Expiry time.Time
}

func NewLocalStore() *LocalStore {
	s := &LocalStore{
		counters: make(map[string]int64),
		blocks:   make(map[string]localBlock),
	}
	go s.cleanupLoop()
	return s
}

func (s *LocalStore) Increment(key string, expiration time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.counters[key]++
	val := s.counters[key]
	
	// Poor man's expiration for counters
	if expiration > 0 {
		go func() {
			time.Sleep(expiration)
			s.mu.Lock()
			delete(s.counters, key)
			s.mu.Unlock()
		}()
	}
	
	return val, nil
}

func (s *LocalStore) Decrement(key string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counters[key]--
	return s.counters[key], nil
}

func (s *LocalStore) GetCounter(key string) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.counters[key], nil
}

func (s *LocalStore) IsBlocked(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	block, ok := s.blocks[key]
	if !ok {
		return false
	}
	
	if !block.Expiry.IsZero() && time.Now().After(block.Expiry) {
		return false
	}
	
	return true
}

func (s *LocalStore) Block(key string, expiration time.Duration, blockType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	expiry := time.Time{}
	if expiration > 0 {
		expiry = time.Now().Add(expiration)
	}
	
	s.blocks[key] = localBlock{
		Type:   blockType,
		Expiry: expiry,
	}
}

func (s *LocalStore) Unblock(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.blocks, key)
	return nil
}

func (s *LocalStore) ListBlocks() (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	res := make(map[string]string)
	for k, v := range s.blocks {
		if v.Expiry.IsZero() || time.Now().Before(v.Expiry) {
			res[k] = v.Type
		}
	}
	return res, nil
}

func (s *LocalStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for k, v := range s.blocks {
			if !v.Expiry.IsZero() && now.After(v.Expiry) {
				delete(s.blocks, k)
			}
		}
		s.mu.Unlock()
	}
}
