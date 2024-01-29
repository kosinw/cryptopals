package cryptopals

import (
	"fmt"
	"testing"
	"time"
)

func TestConvert1A(t *testing.T) {
	t0 := time.Now()

	var (
		in  = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		out = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	)

	fmt.Printf("Test (1A): convert hex to base64 ...\n")

	actual := ToBase64(FromHex(in))

	if actual != out {
		t.Errorf("\nexpected: %v\nactual  : %v\n", out, actual)
	}

	fmt.Printf("  ... Passed -- %v\n", time.Since(t0))
}

func TestXor1B(t *testing.T) {
	t0 := time.Now()

	var (
		a = "1c0111001f010100061a024b53535009181c"
		b = "686974207468652062756c6c277320657965"
		c = "746865206b696420646f6e277420706c6179"
	)

	fmt.Printf("Test (1B): fixed XOR ...\n")

	actual := FixedXor(a, b)

	if actual != c {
		t.Errorf("\nexpected: %v\nactual  : %v\n", c, actual)
	}

	fmt.Printf("  ... Passed -- %v\n", time.Since(t0))
}
