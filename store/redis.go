package store

import (
	"context"
	"time"

	"aegisedge/logger"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	Client *redis.Client
	ctx    context.Context
}

func NewRedisStore(addr string, password string) *RedisStore {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       0,
	})

	return &RedisStore{
		Client: client,
		ctx:    context.Background(),
	}
}

func (s *RedisStore) Get(key string) (string, error) {
	val, err := s.Client.Get(s.ctx, key).Result()
	if err == redis.Nil {
		return "", nil
	}
	return val, err
}

func (s *RedisStore) Set(key string, val string, expiration time.Duration) error {
	return s.Client.Set(s.ctx, key, val, expiration).Err()
}

func (s *RedisStore) Increment(key string, expiration time.Duration) (int64, error) {
	// Atomic LUA script to increment and set expiry if it's a new key.
	// This prevents the "TTL leak" race condition where a key is created but never expired.
	script := `
		local val = redis.call("INCR", KEYS[1])
		if val == 1 then
			redis.call("PEXPIRE", KEYS[1], ARGV[1])
		end
		return val
	`
	val, err := s.Client.Eval(s.ctx, script, []string{key}, int(expiration.Milliseconds())).Int64()
	if err != nil {
		return 0, err
	}
	return val, nil
}

func (s *RedisStore) Decrement(key string) (int64, error) {
	return s.Client.Decr(s.ctx, key).Result()
}

func (s *RedisStore) GetCounter(key string) (int64, error) {
	val, err := s.Client.Get(s.ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}

func (s *RedisStore) IsBlocked(key string) bool {
	exists, err := s.Client.Exists(s.ctx, "block:"+key).Result()
	if err != nil {
		logger.Error("Redis check failed", "err", err)
		return false
	}
	return exists > 0
}

func (s *RedisStore) Block(key string, expiration time.Duration, blockType string) {
	s.Client.Set(s.ctx, "block:"+key, blockType, expiration)
	logger.Info("Distributed block issued", "key", key, "type", blockType, "duration", expiration)
}

func (s *RedisStore) Unblock(key string) error {
	return s.Client.Del(s.ctx, "block:"+key).Err()
}

func (s *RedisStore) ListBlocks() (map[string]string, error) {
	// Use SCAN instead of KEYS for production safety. 
	// KEYS can block the entire Redis instance if the key space is large.
	blocks := make(map[string]string)
	var cursor uint64
	
	for {
		keys, nextCursor, err := s.Client.Scan(s.ctx, cursor, "block:*", 100).Result()
		if err != nil {
			return nil, err
		}
		
		for _, k := range keys {
			val, _ := s.Client.Get(s.ctx, k).Result()
			ip := k[6:] // remove "block:" prefix
			blocks[ip] = val
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	
	return blocks, nil
}
