package cryptopals

import (
	_ "embed"
	"fmt"
	"testing"
	"time"
)

//go:embed data/alice.txt
var AliceCorpus string

func TestConvert1A(t *testing.T) {
	var (
		in  = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		out = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	)

	t0 := time.Now()

	fmt.Printf("Test (1A): convert hex to base64 ...\n")

	actual := ToBase64(FromHex(in))

	if actual != out {
		t.Errorf("\nexpected: %v\nactual  : %v\n", out, actual)
	}

	fmt.Printf("  ... Passed -- %v\n", time.Since(t0))
}

func TestFixedXor1B(t *testing.T) {
	var (
		a = "1c0111001f010100061a024b53535009181c"
		b = "686974207468652062756c6c277320657965"
		c = "746865206b696420646f6e277420706c6179"
	)

	t0 := time.Now()

	fmt.Printf("Test (1B): fixed XOR ...\n")

	actual := ToHex(FixedXor(FromHex(a), FromHex(b)))

	if actual != c {
		t.Errorf("\nexpected: %v\nactual  : %v\n", c, actual)
	}

	fmt.Printf("  ... Passed -- %v\n", time.Since(t0))
}

func TestSingleByteXor1C(t *testing.T) {
	var (
		a = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
		b = "436f6f6b696e67204d432773206c696b65206120706f756e64206f66206261636f6e"
	)

	t0 := time.Now()
	fmt.Printf("Test (1C): single-byte XOR ...\n")

	f := BuildFreqTable(AliceCorpus)
	plaintext, _, _ := f.XorDecrypt(FromHex(a))
	actual := ToHex(plaintext)

	if actual != b {
		t.Errorf("\nexpected: %v\nactual  : %v\n", b, actual)
	}

	fmt.Printf("  ... Passed -- %v\n", time.Since(t0))
}
