package main

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
	"unsafe"
)

// determines whether on 32 or 64 bit architecture
// extracted from package bits
const uintSize = 32 << (^uint(0) >> 63) // 32 or 64
const UintSize = uintSize

// shardCount is the number of paritions a muted is
// divided into such that mutexes can act independently
// of each other to increase speed
const shardCount = 256

type crawledSet struct {
	shards []shard
	number atomic.Int64
}

type shard struct {
	mutex sync.Mutex
	data  map[uint64]struct{}
	// Adds padding to prevent performance overhead from false sharing
	// usenix.org/legacy/publications/library/proceedings/sedms4/full_papers/bolosky.txt
	_ [UintSize - unsafe.Sizeof(sync.Mutex{}) - 8]byte
}

func newCrawledSet() *crawledSet {
	s := &crawledSet{
		shards: make([]shard, shardCount),
	}
	for i := range shardCount {
		s.shards[i] = shard{
			data: make(map[uint64]struct{}),
		}
	}
	return s
}

func (cs *crawledSet) addIfAbsent(url string) bool {
	h := hashURL(url)
	s := &cs.shards[h%shardCount]
	s.mutex.Lock()
	defer s.mutex.Unlock()
	_, ok := s.data[h]
	if ok {
		return false
	}
	s.data[h] = struct{}{}
	cs.number.Add(1)
	return true
}

func (cs *crawledSet) size() int {
	return int(cs.number.Load())
}

func hashURL(url string) uint64 {
	h := fnv.New64a()
	_, err := h.Write([]byte(url))
	if err != nil {
		return 0
	}
	return h.Sum64()
}
