package scheduler

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// Candidate is implemented by a live transport path.
type Candidate interface {
	PathName() string
	ConfiguredWeight() float64
	IsHealthy(now time.Time) bool
	RTT() time.Duration
}

// Scheduler implements smooth weighted round-robin with a modest RTT penalty.
// Every healthy link receives traffic, but unhealthy paths are immediately
// removed. Configured weights should roughly match measured uplink capacity.
type Scheduler struct {
	mu      sync.Mutex
	current map[string]float64
	next    atomic.Uint64
}

func New() *Scheduler {
	return &Scheduler{current: make(map[string]float64)}
}

func (s *Scheduler) Next(paths []Candidate, now time.Time) Candidate {
	s.mu.Lock()
	defer s.mu.Unlock()

	var selected Candidate
	var selectedCurrent float64
	total := 0.0
	active := make(map[string]bool, len(paths))
	for _, path := range paths {
		if !path.IsHealthy(now) {
			continue
		}
		weight := effectiveWeight(path)
		if weight <= 0 {
			continue
		}
		name := path.PathName()
		active[name] = true
		s.current[name] += weight
		total += weight
		if selected == nil || s.current[name] > selectedCurrent {
			selected = path
			selectedCurrent = s.current[name]
		}
	}
	for name := range s.current {
		if !active[name] {
			delete(s.current, name)
		}
	}
	if selected != nil {
		s.current[selected.PathName()] -= total
	}
	return selected
}

func effectiveWeight(path Candidate) float64 {
	weight := path.ConfiguredWeight()
	if weight <= 0 {
		weight = 1
	}
	// RTT influences only 20% of the weight so a high-latency cellular path is
	// still aggregated instead of silently becoming failover-only.
	rtt := path.RTT()
	if rtt > 0 {
		penalty := math.Min(float64(rtt)/float64(500*time.Millisecond), 1)
		weight *= 1 - 0.2*penalty
	}
	return weight
}
