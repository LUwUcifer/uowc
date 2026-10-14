package main

import "sync"

type queue struct {
	linkQueue     []string
	totalQueued   int
	currentQueued int
	mut           sync.RWMutex
}

func (q *queue) enqueue(value string) {
	q.mut.Lock()
	defer q.mut.Unlock()
	q.linkQueue = append(q.linkQueue, value)
	q.currentQueued++
	q.totalQueued++
}

func (q *queue) dequeue() string {
	q.mut.Lock()
	defer q.mut.Unlock()
	if len(q.linkQueue) == 0 {
		return ""
	}
	value := q.linkQueue[0]
	q.linkQueue = q.linkQueue[1:]
	q.currentQueued--
	return value
}

func (q *queue) size() int {
	q.mut.RLock()
	defer q.mut.RUnlock()
	return q.currentQueued
}
