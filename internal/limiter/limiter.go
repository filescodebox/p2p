// Package limiter 提供按键(IP)的令牌桶限流,带空闲回收,防止键空间膨胀。
package limiter

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	janitorInterval = 5 * time.Minute
	idleEvictAfter  = 30 * time.Minute
)

type entry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// Limiter 按键限流器。零值不可用,须经 New 构造。
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	r       rate.Limit
	burst   int
}

// New 构造限流器:每 key 平均 r 事件/秒,桶容量 burst。
// 内部起协程周期回收空闲键,ctx 结束时停止。
func New(ctx context.Context, r rate.Limit, burst int) *Limiter {
	l := &Limiter{
		entries: make(map[string]*entry),
		r:       r,
		burst:   burst,
	}
	go l.janitor(ctx)
	return l
}

// Allow 报告 key 本次事件是否放行。
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		e = &entry{lim: rate.NewLimiter(l.r, l.burst)}
		l.entries[key] = e
	}
	e.lastSeen = time.Now()
	return e.lim.Allow()
}

func (l *Limiter) janitor(ctx context.Context) {
	t := time.NewTicker(janitorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.mu.Lock()
			cutoff := time.Now().Add(-idleEvictAfter)
			for k, e := range l.entries {
				if e.lastSeen.Before(cutoff) {
					delete(l.entries, k)
				}
			}
			l.mu.Unlock()
		}
	}
}
