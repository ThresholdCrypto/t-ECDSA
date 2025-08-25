package kGen

import (
	"crypto/rand"
	"fmt"
	kzg "github.com/arnaucube/kzg-commitments-study"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	nELGa "github.com/mirzazhar/elgamal"
	"log"
	"math/big"
	"t_ECDSA/internal/BKZG"
	"t_ECDSA/pkg/curve"
	"t_ECDSA/pkg/zkSigma"
)

func PVSS(srs *kzg.TrustedSetup, t int, x_i *big.Int, PriKey *nELGa.PrivateKey, secp256k1 curve.Group, G1 curve.Point) (*bn256.G1,
	*bn256.G1, []*big.Int, [][]byte, *zkSigma.ElGamalProof, []curve.Point) {
	// === 1-Polynomial setup ===
	poly := bkzg.GenRanPoly(t, x_i)
	// === 2-Evaluate at 1~(t-1) ===
	y_ji := bkzg.EvalPoly(poly)
	// === 3-Run commit and proof ===
	x_j := make([]*big.Int, len(poly)-2)
	for i := 0; i < len(poly)-2; i++ {
		x_j[i] = big.NewInt(int64(i))
	}
	com := kzg.Commit(srs, poly)
	proof, err := kzg.EvaluationBatchProof(srs, poly, x_j, y_ji)
	if err != nil {
		log.Fatalf("Failed to create batch proof: %v", err)
	}
	// === brocast encrypted value ===
	y_j := make([][]byte, 2*len(y_ji))
	var c1, c2 []byte
	r1, _ := rand.Int(rand.Reader, secp256k1.Order())
	for i := 0; i < len(y_ji); i++ {
		c1, c2, _ := PriKey.PublicKey.Encrypt([]byte(y_ji[i].String()))
		y_j[i*2] = c1
		y_j[i*2+1] = c2
	}
	proof0, points0 := zkSigma.GenLElGEnc(secp256k1, G1, PriKey.P, c1, c2, y_ji[0], r1, []byte("zkproof0"))
	// === Output ===
	fmt.Println("==== KZG Polynomial Commitment Proof ====")
	fmt.Printf("Polynomial: %s\n", kzg.PolynomialToString(poly))
	fmt.Printf("Evaluation Point z: %s\n", x_j)
	fmt.Printf("Expected y = p(z): %s\n", y_ji)
	fmt.Printf("Commitment: %s\n", com.String())
	fmt.Printf("Proof: %s\n", proof.String())
	return com, proof, x_j, y_j, proof0, points0
}
