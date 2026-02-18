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

func (s *RedisStore) Increment(key string, expiration time.Duration) (int64, error) {
	val, err := s.Client.Incr(s.ctx, key).Result()
	if err != nil {
		return 0, err
	}
	
	if val == 1 {
		s.Client.Expire(s.ctx, key, expiration)
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
	// blockType can be "hard", "temp", or "auto"
	s.Client.Set(s.ctx, "block:"+key, blockType, expiration)
	logger.Info("Distributed block issued", "key", key, "type", blockType, "duration", expiration)
}

func (s *RedisStore) Unblock(key string) error {
	return s.Client.Del(s.ctx, "block:"+key).Err()
}

func (s *RedisStore) ListBlocks() (map[string]string, error) {
	keys, err := s.Client.Keys(s.ctx, "block:*").Result()
	if err != nil {
		return nil, err
	}
	
	blocks := make(map[string]string)
	for _, k := range keys {
		val, _ := s.Client.Get(s.ctx, k).Result()
		ip := k[6:] // remove "block:" prefix
		blocks[ip] = val
	}
	return blocks, nil
}
