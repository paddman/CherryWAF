package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	ttl     time.Duration
	buckets map[string]*bucket
	stop    chan struct{}
	done    chan struct{}
	now     func() time.Time
}

type bucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

func New(requestsPerSecond float64, burst int, ttl time.Duration) *Limiter {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	l := &Limiter{
		rate: requestsPerSecond, burst: float64(burst), ttl: ttl,
		buckets: make(map[string]*bucket), stop: make(chan struct{}), done: make(chan struct{}),
		now: time.Now,
	}
	go l.cleanupLoop()
	return l
}

func (l *Limiter) Allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now, lastSeen: now}
		return true
	}

	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

func (l *Limiter) Close() {
	select {
	case <-l.stop:
		return
	default:
		close(l.stop)
		<-l.done
	}
}

func (l *Limiter) cleanupLoop() {
	interval := l.ttl / 2
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer func() {
		ticker.Stop()
		close(l.done)
	}()
	for {
		select {
		case now := <-ticker.C:
			l.mu.Lock()
			for key, b := range l.buckets {
				if now.Sub(b.lastSeen) > l.ttl {
					delete(l.buckets, key)
				}
			}
			l.mu.Unlock()
		case <-l.stop:
			return
		}
	}
}
