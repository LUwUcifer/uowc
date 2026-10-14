package main

import (
	"hash/fnv"
	"sync"
)

type crawledSet struct {
	data   map[uint64]bool
	number int
	mutex  sync.Mutex
}

func newCrawledSet() *crawledSet {
	return &crawledSet{
		data:   make(map[uint64]bool),
		number: 0,
		mutex:  sync.Mutex{},
	}
}

func (cs *crawledSet) add(url string) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.data[hashURL(url)] = true
	cs.number++
}

func (cs *crawledSet) contains(url string) bool {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	_, ok := cs.data[hashURL(url)]
	return ok
}

func (cs *crawledSet) size() int {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	return cs.number
}

func hashURL(url string) uint64 {
	h := fnv.New64a()
	_, err := h.Write([]byte(url))
	if err != nil {
		return 0
	}
	return h.Sum64()
}
