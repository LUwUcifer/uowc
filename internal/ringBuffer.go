package internal

import "errors"

const defaultBufferSize uint32 = 1 << 10

type RingBuffer[T any] struct {
	data []T
	head uint32
	tail uint32
	size uint32
}

func NewRingBuffer[T any](sizeOptional ...uint32) *RingBuffer[T] {
	size := defaultBufferSize
	if len(sizeOptional) > 0 {
		size = sizeOptional[0]
	}
	return &RingBuffer[T]{
		data: make([]T, size),
		head: 0,
		tail: 0,
		size: 0,
	}
}

func (rb *RingBuffer[T]) IsEmpty() bool {
	return rb.size == 0
}

func (rb *RingBuffer[T]) IsFull() bool {
	return rb.size == uint32(cap(rb.data))
}

func (rb *RingBuffer[T]) GetSize() uint32 {
	return rb.size
}

func (rb *RingBuffer[T]) Push(value T) error {
	if rb.IsFull() {
		return errors.New("ring buffer full")
	}
	rb.data[rb.tail] = value
	rb.tail = (rb.tail + 1) % uint32(cap(rb.data))
	rb.size++
	return nil
}

func (rb *RingBuffer[T]) Pop() (T, error) {
	var zero T
	if rb.IsEmpty() {
		//returns garbage value
		return zero, errors.New("ring buffer empty")
	}
	value := rb.data[rb.head]
	rb.data[rb.head] = zero //reclaim memory since golang ring buffers are slices, not arrays
	rb.head = (rb.head + 1) % uint32(cap(rb.data))
	rb.size--
	return value, nil
}

func (rb *RingBuffer[T]) Peek() (T, error) {
	if rb.IsEmpty() {
		var value T
		return value, errors.New("ring buffer empty")
	}
	return rb.data[rb.head], nil
}
