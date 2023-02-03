package logstore_test

import (
	"time"

	"github.com/zitadel/zitadel/internal/logstore"

	"github.com/zitadel/zitadel/internal/query"
)

type emitterOption func(config *logstore.EmitterConfig)

func emitterConfig(options ...emitterOption) *logstore.EmitterConfig {
	cfg := &logstore.EmitterConfig{
		Enabled:         true,
		Keep:            time.Hour,
		CleanupInterval: time.Hour,
		Debounce: &logstore.DebouncerConfig{
			MinFrequency: 0,
			MaxBulkSize:  0,
		},
	}
	for _, opt := range options {
		opt(cfg)
	}
	return cfg
}

func withDebouncerConfig(config *logstore.DebouncerConfig) emitterOption {
	return func(c *logstore.EmitterConfig) {
		c.Debounce = config
	}
}

func withDisabled() emitterOption {
	return func(c *logstore.EmitterConfig) {
		c.Enabled = false
	}
}

func withCleanupping(keep, interval time.Duration) emitterOption {
	return func(c *logstore.EmitterConfig) {
		c.Keep = keep
		c.CleanupInterval = interval
	}
}

type quotaOption func(config *query.CurrentQuotaPeriod)

func quotaConfig(quotaOptions ...quotaOption) query.CurrentQuotaPeriod {
	q := &query.CurrentQuotaPeriod{
		Amount:   90,
		Limit:    false,
		Interval: 90 * time.Second,
	}
	for _, opt := range quotaOptions {
		opt(q)
	}
	return *q
}

func withAmountAndInterval(n int64) quotaOption {
	return func(c *query.CurrentQuotaPeriod) {
		c.Amount = n
		c.Interval = time.Duration(n) * time.Second
	}
}

func withLimiting() quotaOption {
	return func(c *query.CurrentQuotaPeriod) {
		c.Limit = true
	}
}

func repeat(value, times int) []int {
	ints := make([]int, times)
	for i := 0; i < times; i++ {
		ints[i] = value
	}
	return ints
}

func uint64Ptr(n uint64) *uint64 { return &n }
