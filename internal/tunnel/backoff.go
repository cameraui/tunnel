package tunnel

import (
	"math/rand/v2"
	"time"
)

const (
	stableSession = 60 * time.Second
	shortSession  = 5 * time.Second
	dropJitter    = 2 * time.Second
)

type backoff struct {
	base  time.Duration
	limit time.Duration
	rnd   func(n int64) int64
	prev  time.Duration
}

func newBackoff() *backoff {
	return &backoff{base: time.Second, limit: time.Minute, rnd: rand.Int64N}
}

func (b *backoff) next() time.Duration {
	prev := max(b.prev, b.base)
	b.prev = min(b.base+time.Duration(b.rnd(int64(3*prev-b.base))), b.limit)
	return b.prev
}

func (b *backoff) afterSession(lived time.Duration) time.Duration {
	if lived >= stableSession {
		b.prev = 0
	}
	if lived < shortSession {
		return b.next()
	}
	return time.Duration(b.rnd(int64(dropJitter)))
}
