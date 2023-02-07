package ratelimit

import (
	"net"
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	l := &Limiter{
		WindowLimits: []WindowLimit{
			{
				Window: time.Minute,
				Limits: [...]int64{2, 4, 6},
			},
		},
	}

	now := time.Now()
	check := func(exp bool, ip net.IP, tm time.Time, n int64) {
		t.Helper()
		ok := l.CanAdd(ip, tm, n)
		if ok != exp {
			t.Fatalf("canadd, got %v, expected %v", ok, exp)
		}
		ok = l.Add(ip, tm, n)
		if ok != exp {
			t.Fatalf("add, got %v, expected %v", ok, exp)
		}
	}
	check(false, net.ParseIP("10.0.0.1"), now, 3) // past limit
	check(true, net.ParseIP("10.0.0.1"), now, 1)
	check(false, net.ParseIP("10.0.0.1"), now, 2) // now past limit
	check(true, net.ParseIP("10.0.0.1"), now, 1)
	check(false, net.ParseIP("10.0.0.1"), now, 1) // now past limit

	next := now.Add(time.Minute)
	check(true, net.ParseIP("10.0.0.1"), next, 2)  // next minute, should have reset
	check(true, net.ParseIP("10.0.0.2"), next, 2)  // other ip
	check(false, net.ParseIP("10.0.0.3"), next, 2) // yet another ip, ipmasked2 was consumed
	check(true, net.ParseIP("10.0.1.4"), next, 2)  // using ipmasked3
	check(false, net.ParseIP("10.0.2.4"), next, 2) // ipmasked3 consumed
	l.Reset(net.ParseIP("10.0.1.4"), next)
	if !l.CanAdd(net.ParseIP("10.0.1.4"), next, 2) {
		t.Fatalf("reset did not free up count for ip")
	}
	check(true, net.ParseIP("10.0.2.4"), next, 2) // ipmasked3 available again

	l = &Limiter{
		WindowLimits: []WindowLimit{
			{
				Window: time.Minute,
				Limits: [...]int64{1, 2, 3},
			},
			{
				Window: time.Hour,
				Limits: [...]int64{2, 3, 4},
			},
		},
	}

	min1 := time.UnixMilli((time.Now().UnixNano() / int64(time.Hour)) * int64(time.Hour) / int64(time.Millisecond))
	min2 := min1.Add(time.Minute)
	min3 := min1.Add(2 * time.Minute)
	check(true, net.ParseIP("10.0.0.1"), min1, 1)
	check(true, net.ParseIP("10.0.0.1"), min2, 1)
	check(false, net.ParseIP("10.0.0.1"), min3, 1)
	check(true, net.ParseIP("10.0.0.255"), min3, 1)  // ipmasked2 still ok
	check(false, net.ParseIP("10.0.0.255"), min3, 1) // ipmasked2 also full
	check(true, net.ParseIP("10.0.1.1"), min3, 1)    // ipmasked3 still ok
	check(false, net.ParseIP("10.0.1.255"), min3, 1) // ipmasked3 also full
}
