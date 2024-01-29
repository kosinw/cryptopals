package cryptopals

import (
	"bytes"
	"log"
	"strings"
)

// max returns the greater of the two numbers between [a] and [b].
func max(a, b int) int {
	if a > b {
		return a
	}

	return b
}

// assertf crashes the program if [cond] is false.
func assertf(cond bool, fmt string, args ...interface{}) {
	if !cond {
		log.Fatalf(fmt, args...)
	}
}

// isASCII checks if s is an ASCII-encoded string.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > '\u007f' {
			return false
		}
	}

	return true
}

// fromHexDigit converts a single base-16 digit (ASCII) to an integer.
func fromHexDigit(digit byte) int {
	switch {
	case digit >= '0' && digit <= '9':
		return int(digit - '0')
	case digit >= 'a' && digit <= 'f':
		return int(digit-'a') + 10
	case digit >= 'A' && digit <= 'F':
		return int(digit-'A') + 10
	default:
		log.Fatalf("Trying to convert non base-16 digit: %v", digit)
		return -1
	}
}

// FromHex converts a hex-encoded string into a byte slice.
func FromHex(hex string) []byte {
	assertf(isASCII(hex), "Expected \"%v\" to be ASCII-encoded", hex[:16])
	assertf(len(hex)%2 == 0, "Expected \"%v\" to be even length, instead was length %v", hex[:16], len(hex))

	r := strings.NewReader(hex)
	w := new(bytes.Buffer)

	// Every 2 hex characters corresponds to one byte
	w.Grow(len(hex) / 2)

	for r.Len() > 0 {
		first, _ := r.ReadByte()
		second, _ := r.ReadByte()

		X := byte(16*fromHexDigit(first) + fromHexDigit(second))
		w.WriteByte(X)
	}

	return w.Bytes()
}

// ToBase64 converts a raw byte slice into the standard base64 encoding described in RFC 4648.
func ToBase64(src []byte) string {
	// alphabet contains all of the characters of the base64 alphabet.
	// Each "digit" in base64 is 6-bits wide (making a grand total of 64 letters in our alphabet).
	const (
		alphabet     = "ABCDEFGHIJKLMNOPQRSTUVWYXZabcdefghijklmnopqrstuvwxyz0123456789+/"
		maxgroupsize = 3
	)

	r := bytes.NewReader(src)
	w := new(strings.Builder)

	// Every 4 bytes uses 3 letters from alphabet (also take into account potential padding)
	w.Grow((3 * (len(src) + 1)) / 4)

	for r.Len() > 0 {
		var groupsize int
		var group int

		for i := 0; i < maxgroupsize; i++ {
			c, err := r.ReadByte()

			group = group << 8

			if err == nil {
				groupsize++
				group = group | int(c)
			}
		}

		// Add non-padding bytes
		for j := 1; j <= groupsize+1; j++ {
			digit := (group >> ((4 - j) * 6)) & 0x3F
			w.WriteByte(alphabet[digit])
		}

		// Groupsize must either be 1, 2, or 3 since the outerloop would have seized
		// Add padding
		for k := 0; k < (maxgroupsize - groupsize); k++ {
			w.WriteByte('=')
		}
	}

	return w.String()
}
