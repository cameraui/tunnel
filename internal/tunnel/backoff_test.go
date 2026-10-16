package tunnel

import (
	"math/rand/v2"
	"testing"
	"time"
)

func TestBackoffGrowsUpToCap(t *testing.T) {
	b := &backoff{base: time.Second, limit: time.Minute, rnd: func(n int64) int64 { return n - 1 }}

	want := []time.Duration{3 * time.Second, 9 * time.Second, 27 * time.Second, time.Minute, time.Minute}
	for i, w := range want {
		if got := b.next().Round(time.Second); got != w {
			t.Fatalf("delay %d = %v, want %v", i+1, got, w)
		}
	}
}

func TestBackoffStaysWithinBaseAndCap(t *testing.T) {
	b := &backoff{base: time.Second, limit: time.Minute, rnd: rand.Int64N}

	prev := time.Second
	for i := range 1000 {
		d := b.next()
		if d < b.base || d > b.limit || d >= 3*prev {
			t.Fatalf("delay %d = %v, want within [%v, min(%v, %v))", i+1, d, b.base, b.limit, 3*prev)
		}
		prev = d
	}
}

func TestBackoffAfterSession(t *testing.T) {
	newBackoffAt := func(failures int) *backoff {
		b := &backoff{base: time.Second, limit: time.Minute, rnd: func(n int64) int64 { return n - 1 }}
		for range failures {
			b.next()
		}
		return b
	}

	t.Run("short session counts as a failure", func(t *testing.T) {
		b := newBackoffAt(1)
		if got := b.afterSession(time.Second).Round(time.Second); got != 9*time.Second {
			t.Fatalf("delay after a 1s session = %v, want 9s", got)
		}
	})

	t.Run("dropped session reconnects within the jitter window", func(t *testing.T) {
		b := newBackoffAt(0)
		if got := b.afterSession(10 * time.Second); got < 0 || got >= dropJitter {
			t.Fatalf("delay after a 10s session = %v, want within [0, %v)", got, dropJitter)
		}
	})

	t.Run("unstable session keeps the backoff", func(t *testing.T) {
		b := newBackoffAt(5)
		b.afterSession(10 * time.Second)
		if got := b.next(); got != time.Minute {
			t.Fatalf("next failure after a 10s session = %v, want %v", got, time.Minute)
		}
	})

	t.Run("stable session resets the backoff", func(t *testing.T) {
		b := newBackoffAt(5)
		b.afterSession(2 * time.Minute)
		if got := b.next().Round(time.Second); got != 3*time.Second {
			t.Fatalf("next failure after a stable session = %v, want 3s", got)
		}
	})
}
