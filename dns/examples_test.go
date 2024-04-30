package dns_test

import (
	"fmt"
	"log"

	"github.com/mjl-/mox/dns"
)

func ExampleParseDomain() {
	// ASCII-only domain.
	basic, err := dns.ParseDomain("example.com")
	if err != nil {
		log.Fatalf("parse domain: %v", err)
	}
	fmt.Printf("%s\n", basic)

	// IDNA domain xn--74h.example.
	smile, err := dns.ParseDomain("☺.example")
	if err != nil {
		log.Fatalf("parse domain: %v", err)
	}
	fmt.Printf("%s\n", smile)

	// ASCII only domain curl.se in surprisingly allowed spelling.
	surprising, err := dns.ParseDomain("ℂᵤⓇℒ。𝐒🄴")
	if err != nil {
		log.Fatalf("parse domain: %v", err)
	}
	fmt.Printf("%s\n", surprising)

	// Output:
	// example.com
	// ☺.example/xn--74h.example
	// curl.se
}
