package mox

import (
	cryptorand "crypto/rand"
)

func GeneratePassword() string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_;:,<.>/"
	s := ""
	buf := make([]byte, 1)
	for i := 0; i < 12; i++ {
		for {
			cryptorand.Read(buf)
			i := int(buf[0])
			if i+len(chars) > 255 {
				continue // Prevent bias.
			}
			s += string(chars[i%len(chars)])
			break
		}
	}
	return s
}
