package webmail

import (
	"testing"
)

func TestSanitizeHTML(t *testing.T) {
	check := func(in, exp string) {
		t.Helper()
		got, err := sanitizeHTML(in)
		if err != nil {
			t.Fatalf("sanitizeHTML(%q): %v", in, err)
		}
		if got != exp {
			t.Fatalf("sanitizeHTML(%q):\ngot:  %q\nwant: %q", in, got, exp)
		}
	}

	check(`<p>hi</p>`, `<p>hi</p>`)
	check(`<p class="x" id="y" onclick="evil()">hi</p>`, `<p>hi</p>`)
	check(`<script>steal()</script>`, ``)
	check(`<style>p{color:red}</style><p>hi</p>`, `<p>hi</p>`)
	check(`<font color="red"><center>hi</center></font>`, `hi`)
	check(`<b>bold</b> <i>it</i>`, `<b>bold</b> <i>it</i>`)
	check(`<a href="https://example.com">x</a>`, `<a href="https://example.com">x</a>`)
	check(`<a href="javascript:evil()">x</a>`, `<a>x</a>`)
	check(`<a href="mailto:a@b.com">x</a>`, `<a href="mailto:a@b.com">x</a>`)
	check(`<img src="https://t/track.gif" alt="a">`, `[image]`)
	check(`<blockquote><p>q</p></blockquote>`, `<blockquote><p>q</p></blockquote>`)
	check(`<div style="color:red">t</div>`, `<div>t</div>`)
	check(`<!-- comment --><p>hi</p>`, `<p>hi</p>`)
}

func TestSanitizeOutgoingHTML(t *testing.T) {
	check := func(in, exp string) {
		t.Helper()
		got, err := sanitizeOutgoingHTML(in)
		if err != nil {
			t.Fatalf("sanitizeOutgoingHTML(%q): %v", in, err)
		}
		if got != exp {
			t.Fatalf("sanitizeOutgoingHTML(%q):\ngot:  %q\nwant: %q", in, got, exp)
		}
	}

	// Safe style properties are kept (user-chosen font/size/colour survive).
	check(`<span style="color: #ff0000">x</span>`, `<span style="color: #ff0000">x</span>`)
	check(`<span style="font-family: monospace, sans-serif">x</span>`, `<span style="font-family: monospace, sans-serif">x</span>`)
	check(`<span style="font-size: 14px">x</span>`, `<span style="font-size: 14px">x</span>`)
	check(`<p style="text-align: center">x</p>`, `<p style="text-align: center">x</p>`)
	// class and event handlers are still dropped; style is normalized.
	check(`<span style="color:red" class="foo" onclick="e()">x</span>`, `<span style="color: red">x</span>`)
	// Unsafe/unknown properties are dropped, safe ones kept.
	check(`<div style="position: absolute; color: blue">x</div>`, `<div style="color: blue">x</div>`)
	// Resource-loading and non-whitelisted properties are dropped entirely.
	check(`<span style="background-image: url(x)">x</span>`, `<span>x</span>`)
	check(`<span style="background-color: url(javascript:x)">x</span>`, `<span>x</span>`)
	// Scripts are still removed.
	check(`<script>steal()</script><span style="color: green">y</span>`, `<span style="color: green">y</span>`)
	// Exactly what the Squire editor emits (class + trailing semicolon): class dropped,
	// style kept and normalized.
	check(`<span class="color" style="color:#ff0000">x</span>`, `<span style="color: #ff0000">x</span>`)
	check(`<span class="font" style="font-family: monospace, sans-serif;">x</span>`, `<span style="font-family: monospace, sans-serif">x</span>`)
	check(`<span class="size" style="font-size: 1.35em">x</span>`, `<span style="font-size: 1.35em">x</span>`)
	// Outgoing blockquotes get an inline style so they render as a quote in the
	// recipient's client (which lacks our stylesheet).
	check(`<blockquote><p>q</p></blockquote>`, `<blockquote style="margin: 0 0 0 0.8ex; border-left: 2px solid #ccc; padding-left: 1ex"><p>q</p></blockquote>`)
}
