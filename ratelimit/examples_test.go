package ratelimit_test

import (
	"fmt"
	"net"
	"time"

	"github.com/mjl-/mox/ratelimit"
)

func ExampleLimiter() {
	// Make a new rate limit that has maxima per minute, hour and day. The maxima are
	// tracked per ipmasked1 (ipv4 /32 or ipv6 /64), ipmasked2 (ipv4 /26 or ipv6 /48)
	// and ipmasked3 (ipv4 /21 or ipv6 /32).
	//
	// It is common to allow short bursts (with a narrow window), but not allow a high
	// sustained rate (with wide window).
	limit := ratelimit.Limiter{
		WindowLimits: []ratelimit.WindowLimit{
			{Window: time.Minute, Limits: [...]int64{2, 3, 4}},
			{Window: time.Hour, Limits: [...]int64{4, 6, 8}},
			{Window: 24 * time.Hour, Limits: [...]int64{20, 40, 60}},
		},
	}

	tm, _ := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")

	fmt.Println("1:", limit.Add(net.ParseIP("127.0.0.1"), tm, 1))                    // Success.
	fmt.Println("2:", limit.Add(net.ParseIP("127.0.0.1"), tm, 1))                    // Success.
	fmt.Println("3:", limit.Add(net.ParseIP("127.0.0.1"), tm, 1))                    // Failure, too many from same ip.
	fmt.Println("4:", limit.Add(net.ParseIP("127.0.0.2"), tm, 1))                    // Success, different IP, though nearby.
	fmt.Println("5:", limit.Add(net.ParseIP("127.0.0.2"), tm, 1))                    // Failure, hits ipmasked2 check.
	fmt.Println("6:", limit.Add(net.ParseIP("127.0.0.1"), tm.Add(time.Minute), 1))   // Success, in next minute.
	fmt.Println("7:", limit.Add(net.ParseIP("127.0.0.1"), tm.Add(2*time.Minute), 1)) // Success, in another minute.
	fmt.Println("8:", limit.Add(net.ParseIP("127.0.0.1"), tm.Add(3*time.Minute), 1)) // Failure, hitting hourly window for ipmasked1.
	limit.Reset(net.ParseIP("127.0.0.1"), tm.Add(3*time.Minute))
	fmt.Println("9:", limit.Add(net.ParseIP("127.0.0.1"), tm.Add(3*time.Minute), 1)) // Success.

	// Output:
	// 1: true
	// 2: true
	// 3: false
	// 4: true
	// 5: false
	// 6: true
	// 7: true
	// 8: false
	// 9: true
}
