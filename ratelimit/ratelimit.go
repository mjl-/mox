// Package ratelimit provides a simple window-based rate limiter.
package ratelimit

import (
	"net"
	"sync"
	"time"
)

// Limiter is a simple rate limiter with one or more fixed windows, e.g. the
// last minute/hour/day/week, working on three classes/subnets of an IP.
type Limiter struct {
	sync.Mutex
	WindowLimits []WindowLimit
	ipmasked     [3][16]byte
}

// WindowLimit holds counters for one window, with limits for each IP class/subnet.
type WindowLimit struct {
	Window time.Duration
	Limits [3]int64 // For "ipmasked1" through "ipmasked3".
	Time   uint32   // Time/Window.
	Counts map[struct {
		Index    uint8
		IPMasked [16]byte
	}]int64
}

// Add attempts to consume "n" items from the rate limiter. If the total for this
// key and this interval would exceed limit, "n" is not counted and false is
// returned. If now represents a different time interval, all counts are reset.
func (l *Limiter) Add(ip net.IP, tm time.Time, n int64) bool {
	return l.checkAdd(true, ip, tm, n)
}

// CanAdd returns if n could be added to the limiter.
func (l *Limiter) CanAdd(ip net.IP, tm time.Time, n int64) bool {
	return l.checkAdd(false, ip, tm, n)
}

func (l *Limiter) checkAdd(add bool, ip net.IP, tm time.Time, n int64) bool {
	l.Lock()
	defer l.Unlock()

	// First check.
	for i, pl := range l.WindowLimits {
		t := uint32(tm.UnixNano() / int64(pl.Window))

		if t > pl.Time || pl.Counts == nil {
			l.WindowLimits[i].Time = t
			pl.Counts = map[struct {
				Index    uint8
				IPMasked [16]byte
			}]int64{} // Used below.
			l.WindowLimits[i].Counts = pl.Counts
		}

		for j := 0; j < 3; j++ {
			if i == 0 {
				l.ipmasked[j] = l.maskIP(j, ip)
			}

			v := pl.Counts[struct {
				Index    uint8
				IPMasked [16]byte
			}{uint8(j), l.ipmasked[j]}]
			if v+n > pl.Limits[j] {
				return false
			}
		}
	}
	if !add {
		return true
	}
	// Finally record.
	for _, pl := range l.WindowLimits {
		for j := 0; j < 3; j++ {
			pl.Counts[struct {
				Index    uint8
				IPMasked [16]byte
			}{uint8(j), l.ipmasked[j]}] += n
		}
	}
	return true
}

// Reset sets the counter to 0 for key and ip, and subtracts from the ipmasked counts.
func (l *Limiter) Reset(ip net.IP, tm time.Time) {
	l.Lock()
	defer l.Unlock()

	// Prepare masked ip's.
	for i := 0; i < 3; i++ {
		l.ipmasked[i] = l.maskIP(i, ip)
	}

	for _, pl := range l.WindowLimits {
		t := uint32(tm.UnixNano() / int64(pl.Window))
		if t != pl.Time || pl.Counts == nil {
			continue
		}
		var n int64
		for j := 0; j < 3; j++ {
			k := struct {
				Index    uint8
				IPMasked [16]byte
			}{uint8(j), l.ipmasked[j]}
			if j == 0 {
				n = pl.Counts[k]
			}
			if pl.Counts != nil {
				pl.Counts[k] -= n
			}
		}
	}
}

func (l *Limiter) maskIP(i int, ip net.IP) [16]byte {
	isv4 := ip.To4() != nil

	var ipmasked net.IP
	if isv4 {
		switch i {
		case 0:
			ipmasked = ip
		case 1:
			ipmasked = ip.Mask(net.CIDRMask(26, 32))
		case 2:
			ipmasked = ip.Mask(net.CIDRMask(21, 32))
		default:
			panic("missing case for maskip ipv4")
		}
	} else {
		switch i {
		case 0:
			ipmasked = ip.Mask(net.CIDRMask(64, 128))
		case 1:
			ipmasked = ip.Mask(net.CIDRMask(48, 128))
		case 2:
			ipmasked = ip.Mask(net.CIDRMask(32, 128))
		default:
			panic("missing case for masking ipv6")
		}
	}
	return *(*[16]byte)(ipmasked.To16())
}
