package group

import (
	"crypto/rand"
	"fmt"
	"github.com/lavode/distributed-elgamal/elgamal"
	"math/big"
)

// SchnorrGroup represents a q-order subgroup of the multiplicative group of
// integers modulo p.
type SchnorrGroup struct {
	// Prime modulus of multiplicative group of integers modulo p, (Z/pZ)*
	P *big.Int
	// Prime order of subgroup G of (Z/pZ)*
	Q *big.Int
	// Generator of subgroup G
	G *big.Int
}

// GenerateSchnorrGroup generates a Schnorr subgroup of prime order Q, with q
// of length qBits, within the multiplicative group of integers modulo P, with
// p of length pBits.
//
// qBits must be strictly less than pBits, otherwise an error is returned.  An
// error may also be returned if sourcing of cryptographically secure
// randomness fails.
func GenerateSchnorrGroup(pBits int, qBits int) (SchnorrGroup, error) {
	var err error
	schnorr := SchnorrGroup{}

	if qBits >= pBits {
		return schnorr, fmt.Errorf("qbits must be < pbits")
	}

	// Starting with q-order subgroup
	schnorr.Q, err = rand.Prime(rand.Reader, qBits)
	if err != nil {
		return schnorr, err
	}

	// Find a prime p such that p = q*r + 1 for some integer r
	schnorr.P = big.NewInt(0)
	for !schnorr.P.ProbablyPrime(32) {
		rBits := pBits - qBits
		r, err := elgamal.RandomBits(rBits)
		if err != nil {
			return schnorr, err
		}

		// At this point, r and q both are guaranteed to have their
		// highest two bits as 1. As such, the product of the two has a
		// bit length of exactly pbits. Further the product cannot be
		// the bigmost possible pBits number, so adding 1 will not
		// cause it to overflow.

		// p = r * q + 1
		schnorr.P.SetBytes(r)
		schnorr.P.Mul(schnorr.P, schnorr.Q)
		schnorr.P.Add(schnorr.P, big.NewInt(1))
	}

	// Finally find a generator by picking random values 1 < h < p such that g = h^r mod p != 1
	schnorr.G = big.NewInt(1)
	for {
		// rand.Int produces in [0, max), we want [2, p).
		var max = &big.Int{}
		max.Set(schnorr.P)
		max.Sub(max, big.NewInt(2))

		h, err := rand.Int(rand.Reader, max) // [0, p-2)
		if err != nil {
			return schnorr, err
		}
		h.Add(h, big.NewInt(2)) // [2, p)

		var exp = &big.Int{}
		exp.Sub(schnorr.P, big.NewInt(1))
		exp.Div(exp, schnorr.Q)

		schnorr.G.Exp(h, exp, schnorr.P)

		if schnorr.G.Cmp(big.NewInt(1)) != 0 {
			break
		}
	}

	return schnorr, nil
}
