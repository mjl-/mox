package mox

import (
	cryptorand "crypto/rand"
	"strings"
)

func GeneratePassword() string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_;:,<.>/"
	var s strings.Builder
	buf := make([]byte, 1)
	for range 12 {
		for {
			cryptorand.Read(buf)
			i := int(buf[0])
			if i+len(chars) > 255 {
				continue // Prevent bias.
			}
			s.WriteString(string(chars[i%len(chars)]))
			break
		}
	}
	return s.String()
}
