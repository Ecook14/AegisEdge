package store

import (
	"sync"
	"time"
)

// localData holds a value with an optional expiry time.
type localData struct {
	value  string
	expiry time.Time // zero = no expiry
}

// localCounter holds a counter with an optional expiry time.
type localCounter struct {
	count  int64
	expiry time.Time
}

type LocalStore struct {
	counters map[string]localCounter
	blocks   map[string]localBlock
	data     map[string]localData
	mu       sync.RWMutex
	stop     chan struct{}
}

type localBlock struct {
	Type   string
	Expiry time.Time
}

func NewLocalStore() *LocalStore {
	s := &LocalStore{
		counters: make(map[string]localCounter),
		blocks:   make(map[string]localBlock),
		data:     make(map[string]localData),
		stop:     make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

// Close stops the background cleanup goroutine.
func (s *LocalStore) Close() error {
	close(s.stop)
	return nil
}

func (s *LocalStore) Get(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d := s.data[key]
	if !d.expiry.IsZero() && time.Now().After(d.expiry) {
		return "", nil // expired
	}
	return d.value, nil
}

func (s *LocalStore) Set(key string, val string, expiration time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry := time.Time{}
	if expiration > 0 {
		expiry = time.Now().Add(expiration)
	}
	s.data[key] = localData{value: val, expiry: expiry}
	return nil
}

func (s *LocalStore) Increment(key string, expiration time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c := s.counters[key]
	// Only set the expiry on the first increment for this key (new window).
	// Subsequent increments within the window extend nothing — correct sliding window behaviour.
	if c.count == 0 && expiration > 0 {
		c.expiry = time.Now().Add(expiration)
	}
	c.count++
	s.counters[key] = c
	return c.count, nil
}

func (s *LocalStore) Decrement(key string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.counters[key]
	c.count--
	s.counters[key] = c
	return c.count, nil
}

func (s *LocalStore) GetCounter(key string) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.counters[key].count, nil
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
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			// Evict expired blocks
			for k, v := range s.blocks {
				if !v.Expiry.IsZero() && now.After(v.Expiry) {
					delete(s.blocks, k)
				}
			}
			// Evict expired counters (windows that have closed)
			for k, c := range s.counters {
				if !c.expiry.IsZero() && now.After(c.expiry) {
					delete(s.counters, k)
				}
			}
			// Evict expired data entries
			for k, d := range s.data {
				if !d.expiry.IsZero() && now.After(d.expiry) {
					delete(s.data, k)
				}
			}
			s.mu.Unlock()
		case <-s.stop:
			return
		}
	}
}
