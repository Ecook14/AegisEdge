package store

import "time"

// Storer is the common interface for all storage backends (Redis, In-Memory)
type Storer interface {
	Increment(key string, expiration time.Duration) (int64, error)
	Decrement(key string) (int64, error)
	GetCounter(key string) (int64, error)
	IsBlocked(key string) bool
	Block(key string, expiration time.Duration, blockType string)
	Unblock(key string) error
	ListBlocks() (map[string]string, error)
}
