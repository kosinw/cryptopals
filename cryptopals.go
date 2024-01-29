package cryptopals

import (
	"bytes"
	"log"
	"strings"
)

// max returns the greater of the two numbers between a and b.
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
	assertf(isASCII(hex), "FromHex(): Expected \"%v\" to be ASCII-encoded", hex[:16])
	assertf(len(hex)%2 == 0, "FromHex(): Expected \"%v\" to be even length, instead was length %v", hex[:16], len(hex))

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

// ToHex converts from a byte slice to a hex-encoded string.
func ToHex(data []byte) string {
	const alphabet = "0123456789abcdef"

	r := bytes.NewReader(data)
	w := new(strings.Builder)

	w.Grow(len(data) * 2)

	for r.Len() > 0 {
		x, err := r.ReadByte()

		if err != nil {
			panic(err)
		}

		a := x & 0x0F
		b := (x >> 4) & 0x0F

		w.WriteByte(alphabet[b])
		w.WriteByte(alphabet[a])
	}

	return w.String()
}

// ToBase64 converts a raw byte slice into the standard base64 encoding described in RFC 4648.
func ToBase64(src []byte) string {
	// alphabet contains all of the characters of the base64 alphabet.
	// Each "digit" in base64 is 6-bits wide (making a grand total of 64 letters in our alphabet).
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWYXZabcdefghijklmnopqrstuvwxyz0123456789+/"

	r := bytes.NewReader(src)
	w := new(strings.Builder)

	// Every 4 bytes uses 3 letters from alphabet (also take into account potential padding)
	w.Grow(len(src) * 4 / 3)

	for r.Len() > 0 {
		var groupsize int
		var group int

		for i := 0; i < 3; i++ {
			c, err := r.ReadByte()

			group = group << 8

			if err == nil {
				groupsize++
				group = group | int(c)
			}
		}

		for j := 1; j <= groupsize+1; j++ {
			digit := (group >> ((4 - j) * 6)) & 0x3F
			w.WriteByte(alphabet[digit])
		}

		for k := 0; k < (3 - groupsize); k++ {
			w.WriteByte('=')
		}
	}

	return w.String()
}

// FixedXor takes two buffers, a and b, of equal size encoded in hex and
// returns a new buffer where every byte in a is xorred with the corresponding
// byte in b.
func FixedXor(a []byte, b []byte) []byte {
	assertf(len(a) == len(b), "FixedXOR(): Both buffers most be same size\n")

	w := make([]byte, len(a))

	for i := 0; i < len(a); i++ {
		w[i] = a[i] ^ b[i]
	}

	return w
}

// FreqTable is a data structure representing a table of bytes to frequency which is used
// for [frequency analysis].
//
// [frequency analysis]: https://en.wikipedia.org/wiki/Frequency_analysis
type FreqTable struct {
	table map[byte]float64
}

// BuildFreqTable creates a new frequency table based on the text in corpus.
func BuildFreqTable(corpus []byte) *FreqTable {
	r := &FreqTable{table: map[byte]float64{}}
	n := len(corpus)

	for i := 0; i < n; i++ {
		r.table[corpus[i]] += 1.0
	}

	for k, v := range r.table {
		r.table[k] = v / float64(n)
	}

	return r
}

// score assigns a numerical score to text by using the internal frequency table.
func (f *FreqTable) score(text []byte) float64 {
	score := 0.0

	for i := 0; i < len(text); i++ {
		score += f.table[text[i]]
	}

	return score
}

// xor returns a string where every byte in a has been xorred with b.
func (f *FreqTable) xor(a []byte, b byte) []byte {
	w := make([]byte, len(a))

	for i := 0; i < len(a); i++ {
		w[i] = a[i] ^ b
	}

	return w
}

// XorDecrypt decrypts the given string by trying an exhaustive single-byte xor
// and using the scoring from the frequency table to decide which byte it is.
func (f *FreqTable) XorDecrypt(ciphertext []byte) ([]byte, byte, float64) {
	s := ciphertext
	b := byte(0)
	t := f.score(s)

	for i := 0x01; i < 0x100; i++ {
		bb := byte(i)
		ss := f.xor(ciphertext, bb)
		tt := f.score(ss)

		if tt > t {
			s = ss
			b = bb
			t = tt
		}
	}

	return s, b, t
}

// DetectEncryptedLine finds the XOR encrypted line given a slice of lines.
func (f *FreqTable) DetectEncryptedLine(ciphertexts [][]byte) ([]byte, byte, float64) {
	if len(ciphertexts) == 0 {
		return nil, 0, 0.0
	}

	plaintext, key, score := f.XorDecrypt(ciphertexts[0])

	for i := 1; i < len(ciphertexts); i++ {
		pp, kk, ss := f.XorDecrypt(ciphertexts[i])

		if ss > score {
			plaintext = pp
			key = kk
			score = ss
		}
	}

	return plaintext, key, score
}
