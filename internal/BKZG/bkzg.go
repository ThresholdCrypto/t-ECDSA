package bkzg

import (
	"fmt"
	kzg "github.com/arnaucube/kzg-commitments-study"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"log"
	"math"
	"math/big"
	"math/rand"
	"time"
)

type Output struct {
	Z          string //`json:"z"`
	Y          string //`json:"y"`
	Polynomial string //`json:"polynomial"`
	Commitment string //`json:"commitment"`
	Proof      string //`json:"proof"`
	Verified   bool   //`json:"verified"`
}

func powInt(x, y int) int {
	return int(math.Pow(float64(x), float64(y)))
}

func GenRanPoly(degree int, x_i *big.Int) []*big.Int {
	rng := rand.New(rand.NewSource(time.Now().Unix()))
	poly := make([]*big.Int, degree+1)
	poly[0] = x_i
	for i := 1; i < len(poly); i++ {
		poly[i] = big.NewInt(rng.Int63n(10)) // random coeffs 0–9
		fmt.Println(poly[i])
	}
	return poly
}

func EvalPoly(poly []*big.Int) []*big.Int {
	yj := make([]*big.Int, len(poly)-2)
	for i := 0; i < len(poly)-2; i++ {
		result := 0
		for j, coeff := range poly {
			result += int(coeff.Int64()) * powInt(i, j)
		}
		yj[i] = big.NewInt(int64(result))
	}
	return yj
}

func RunProof(ts *kzg.TrustedSetup, p []*big.Int, z *big.Int, y *big.Int) (*bn256.G1, *bn256.G1) {
	proof, err := kzg.EvaluationProof(ts, p, z, y)
	if err != nil {
		log.Fatalf("Failed to generate proof: %v", err)
	}
	c := kzg.Commit(ts, p)
	return proof, c
}
