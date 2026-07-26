// Package reorder restores the global packet order after packets have been
// striped over paths with different latency. A bounded wait prevents one lost
// UDP datagram from stalling the tunnel.
package reorder

import (
	"sync"
	"time"
)

type Result struct {
	Packets [][]byte
	Skipped uint64
}

type Buffer struct {
	mu         sync.Mutex
	expected   uint64
	pending    map[uint64][]byte
	gapSince   time.Time
	maxPackets int
	maxDelay   time.Duration
}

func New(maxPackets int, maxDelay time.Duration) *Buffer {
	if maxPackets < 16 {
		maxPackets = 16
	}
	if maxDelay <= 0 {
		maxDelay = 80 * time.Millisecond
	}
	return &Buffer{
		expected:   1,
		pending:    make(map[uint64][]byte),
		maxPackets: maxPackets,
		maxDelay:   maxDelay,
	}
}

func (b *Buffer) MaxDelay() time.Duration { return b.maxDelay }

func (b *Buffer) Reset() {
	b.mu.Lock()
	b.expected = 1
	b.pending = make(map[uint64][]byte)
	b.gapSince = time.Time{}
	b.mu.Unlock()
}

func (b *Buffer) Push(sequence uint64, packet []byte, now time.Time) Result {
	b.mu.Lock()
	defer b.mu.Unlock()

	if sequence < b.expected {
		return Result{}
	}
	if sequence == b.expected {
		result := Result{Packets: [][]byte{packet}}
		b.expected++
		b.drain(&result)
		return result
	}
	if _, duplicate := b.pending[sequence]; duplicate {
		return Result{}
	}
	b.pending[sequence] = packet
	if b.gapSince.IsZero() {
		b.gapSince = now
	}
	if len(b.pending) >= b.maxPackets || now.Sub(b.gapSince) >= b.maxDelay {
		return b.forceDrain()
	}
	return Result{}
}

func (b *Buffer) FlushExpired(now time.Time) Result {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.pending) == 0 || b.gapSince.IsZero() || now.Sub(b.gapSince) < b.maxDelay {
		return Result{}
	}
	return b.forceDrain()
}

func (b *Buffer) drain(result *Result) {
	for {
		packet, ok := b.pending[b.expected]
		if !ok {
			break
		}
		delete(b.pending, b.expected)
		result.Packets = append(result.Packets, packet)
		b.expected++
	}
	if len(b.pending) == 0 {
		b.gapSince = time.Time{}
	} else {
		b.gapSince = time.Now()
	}
}

func (b *Buffer) forceDrain() Result {
	if len(b.pending) == 0 {
		return Result{}
	}
	lowest := uint64(^uint64(0))
	for sequence := range b.pending {
		if sequence < lowest {
			lowest = sequence
		}
	}
	result := Result{Skipped: lowest - b.expected}
	b.expected = lowest
	b.drain(&result)
	return result
}
