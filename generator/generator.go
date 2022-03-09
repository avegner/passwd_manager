package generator

import (
	"crypto/rand"
	"math/big"
)

// printable chars in ASCII:
// * first - 33  = '!'
// * last  - 126 = '~'

const (
	firstPrintChar = '!'
	lastPrintChar  = '~'
	maxRandInt     = int64(lastPrintChar) - int64(firstPrintChar) + int64(1)
)

func Generate(leng uint) (string, error) {
	buf := make([]byte, leng)

	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(maxRandInt))
		if err != nil {
			return "", err
		}
		buf[i] = byte(n.Int64() + firstPrintChar)
	}

	return string(buf), nil
}
