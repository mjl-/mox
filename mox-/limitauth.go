package mox

import (
	"time"

	"github.com/mjl-/mox/ratelimit"
)

var LimiterFailedAuth *ratelimit.Limiter

func init() {
	LimitersInit()
}

// LimitesrsInit initializes the failed auth rate limiter.
func LimitersInit() {
	LimiterFailedAuth = &ratelimit.Limiter{
		WindowLimits: []ratelimit.WindowLimit{
			{
				// Max 10 failures/minute for ipmasked1, 30 or ipmasked2, 90 for ipmasked3.
				Window: time.Minute,
				Limits: [...]int64{10, 30, 90},
			},
			{
				Window: 24 * time.Hour,
				Limits: [...]int64{50, 150, 450},
			},
		},
	}
}
