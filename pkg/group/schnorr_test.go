package group

import (
	"math/big"
	"testing"
)

func TestGenerateSchnorrGroup(t *testing.T) {
	pBits := 1024
	qBits := 128
	schnorr, err := GenerateSchnorrGroup(pBits, qBits)
	if err != nil {
		t.Fatalf("Error generating Schnorr group: %v", err)
	}

	if !schnorr.P.ProbablyPrime(32) {
		t.Errorf("P is not prime; got %d", schnorr.P)
	}
	if schnorr.P.BitLen() != pBits {
		t.Errorf("Expected p to have bit length %d; got %d", pBits, schnorr.P.BitLen())
	}

	if !schnorr.Q.ProbablyPrime(32) {
		t.Errorf("Q is not prime; got %d", schnorr.Q)
	}
	if schnorr.Q.BitLen() != qBits {
		t.Errorf("Expected q to have bit length %d; got %d", qBits, schnorr.Q.BitLen())
	}

	// p must be of the form p = q*r + 1, for some integer q. That is `p mod q = 1`
	var rem = &big.Int{}
	rem.Rem(schnorr.P, schnorr.Q)
	if rem.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("Expected p = q * r + 1; got p = %d, q = %d", schnorr.P, schnorr.Q)
	}

	// In order to be a generator, `g` must not be congruent to 1 mod p
	rem.Mod(schnorr.G, schnorr.P)
	if rem.Cmp(big.NewInt(1)) == 0 {
		t.Errorf("Expected g to be a generator of G; got g = %d, p = %d", schnorr.G, schnorr.P)
	}
	// Sanity check - it shouldn't be the default value of a big.Int either
	if schnorr.G.Cmp(big.NewInt(0)) == 0 {
		t.Errorf("Expected g != 0")
	}

	_, err = GenerateSchnorrGroup(10, 10)
	if err == nil {
		t.Errorf("Expected error when pbits <= qbits; got none")
	}
}
