package internal

import "sync"

// Job is one unit of crawl work
// Depth is the number of link hops from the seed.
type Job struct {
	URL   string
	Depth int
}

// Queue is a bounded, blocking, thread-safe FIFO frontier built on RingBuffer.
//
// RingBuffer itself is not thread-safe, so every access goes through q.mu.
// Capacity is fixed at construction, which doubles as the max-frontier cap:
// when the buffer is full, Enqueue drops the job and reports false.
//
// Termination: Dequeue counts a job as in-flight until the worker calls Done.
// When the buffer is empty and nothing is in flight, no more work can ever
// appear, so the queue closes itself and all blocked Dequeue calls return false.
type Queue struct {
	mu       sync.Mutex
	notEmpty *sync.Cond
	buf      *RingBuffer[Job]
	inFlight int
	closed   bool

	totalQueued int64
	dropped     int64
}

func NewQueue(capacity uint32) *Queue {
	if capacity == 0 {
		capacity = 1 // RingBuffer takes a modulo by capacity, so 0 would panic
	}
	q := &Queue{buf: NewRingBuffer[Job](capacity)}
	q.notEmpty = sync.NewCond(&q.mu)
	return q
}

// Enqueue adds a job. It returns false if the queue is full or closed.
// It never blocks, so workers that feed the queue cannot deadlock on it.
func (q *Queue) Enqueue(j Job) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	if err := q.buf.Push(j); err != nil { // full
		q.dropped++
		return false
	}
	q.totalQueued++
	q.notEmpty.Signal()
	return true
}

// Dequeue blocks until a job is available. It returns false once the crawl is
// finished (queue empty and nothing in flight) or the queue was closed.
// Every successful Dequeue must be paired with exactly one Done call.
func (q *Queue) Dequeue() (Job, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.buf.IsEmpty() {
		if q.closed {
			return Job{}, false
		}
		if q.inFlight == 0 {
			q.closed = true
			q.notEmpty.Broadcast()
			return Job{}, false
		}
		q.notEmpty.Wait()
	}
	j, _ := q.buf.Pop() // cannot fail: buffer is non-empty under the lock
	q.inFlight++
	return j, true
}

// Done marks a dequeued job as finished. Call it after the worker has
// enqueued every link it found, so the termination check sees them.
func (q *Queue) Done() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.inFlight--
	if q.inFlight == 0 && q.buf.IsEmpty() {
		q.closed = true
		q.notEmpty.Broadcast()
	}
}

// Close stops the queue early (for example on context cancellation).
// Pending jobs are left unprocessed and blocked workers are released.
func (q *Queue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.notEmpty.Broadcast()
}

// Size returns the number of jobs waiting in the queue.
func (q *Queue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return int(q.buf.GetSize())
}

// Stats returns counters for metrics.
func (q *Queue) Stats() (queued, dropped int64, inFlight int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.totalQueued, q.dropped, q.inFlight
}
