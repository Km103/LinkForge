package scheduler

import (
	"testing"
	"time"
)

type testPath struct {
	name    string
	weight  float64
	healthy bool
	rtt     time.Duration
}

func (p testPath) PathName() string          { return p.name }
func (p testPath) ConfiguredWeight() float64 { return p.weight }
func (p testPath) IsHealthy(time.Time) bool  { return p.healthy }
func (p testPath) RTT() time.Duration        { return p.rtt }

func TestWeightedDistributionAndFailover(t *testing.T) {
	scheduler := New()
	paths := []Candidate{
		testPath{name: "wifi", weight: 3, healthy: true},
		testPath{name: "usb", weight: 1, healthy: true},
		testPath{name: "down", weight: 100, healthy: false},
	}
	counts := map[string]int{}
	for i := 0; i < 400; i++ {
		counts[scheduler.Next(paths, time.Now()).PathName()]++
	}
	if counts["wifi"] != 300 || counts["usb"] != 100 || counts["down"] != 0 {
		t.Fatalf("unexpected weighted distribution: %#v", counts)
	}
}
