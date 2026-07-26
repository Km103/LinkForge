package reorder

import (
	"testing"
	"time"
)

func TestOrdersPacketsAcrossPaths(t *testing.T) {
	now := time.Now()
	buffer := New(64, 50*time.Millisecond)
	if result := buffer.Push(2, []byte{2}, now); len(result.Packets) != 0 {
		t.Fatal("sequence 2 should wait for sequence 1")
	}
	result := buffer.Push(1, []byte{1}, now.Add(time.Millisecond))
	if len(result.Packets) != 2 || result.Packets[0][0] != 1 || result.Packets[1][0] != 2 {
		t.Fatalf("unexpected delivery order: %#v", result.Packets)
	}
}

func TestSkipsLostPacketAfterDeadline(t *testing.T) {
	now := time.Now()
	buffer := New(64, 10*time.Millisecond)
	buffer.Push(2, []byte{2}, now)
	result := buffer.FlushExpired(now.Add(11 * time.Millisecond))
	if result.Skipped != 1 || len(result.Packets) != 1 || result.Packets[0][0] != 2 {
		t.Fatalf("unexpected forced delivery: %#v", result)
	}
}

func TestWindowBoundForcesDelivery(t *testing.T) {
	buffer := New(16, time.Hour)
	now := time.Now()
	var result Result
	for sequence := uint64(2); sequence <= 17; sequence++ {
		result = buffer.Push(sequence, []byte{byte(sequence)}, now)
	}
	if result.Skipped != 1 || len(result.Packets) != 16 {
		t.Fatalf("unexpected bounded delivery: %#v", result)
	}
}
