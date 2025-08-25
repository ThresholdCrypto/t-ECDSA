package utils

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
)

// RandomBits returns bits random bits suitable for cryptographic usage.
//
// Bits must be > 2. If bits is not a multiple of 8, the leading bits of the
// first byte (at index 0) will be forced to 0.
//
// It is also ensured that the two most significant bit are 1. This costs two
// bits of randomness, but helps with multiplying such numbers together. As
// such it is not suitable for use with low bit counts.
func RandomBits(bits int) ([]byte, error) {
	bytes := int(math.Ceil(float64(bits) / 8))
	out := make([]byte, bytes)

	if bits <= 2 {
		return out, fmt.Errorf("Bits must be > 2")
	}

	_, err := rand.Read(out)
	if err != nil {
		return out, err
	}

	zeroLeadingBits := 8*bytes - bits
	// Zero leading bits, if requested not a multiple of eight
	out[0] = out[0] & (0xFF >> zeroLeadingBits)
	// Set leading two (*requested*) bits to 1
	out[0] = out[0] | (0xC0 >> zeroLeadingBits)
	return out, nil
}
func RandomZq(q *big.Int) (*big.Int, error) {
	//[0, q-1]
	//rand.Int
	x, err := rand.Int(rand.Reader, q)
	if err != nil {
		return nil, fmt.Errorf("fail to generate random value: %v", err)
	}
	return x, nil
}
func CalComm(x *big.Int) int {
	xBytes := x.Bytes()
	return len(xBytes)
}
