package main

import (
	"crypto/rand"
	"fmt"
	"github.com/arnaucube/kzg-commitments-study"
	"github.com/lavode/secret-sharing/gf"
	nELGa "github.com/mirzazhar/elgamal"
	"log"
	"math/big"
	"strconv"
	"t_ECDSA/cmd/Sign"
	"t_ECDSA/cmd/kGen"
	"t_ECDSA/internal/BMtP"
	"t_ECDSA/pkg/curve"
	"t_ECDSA/pkg/group"
	"t_ECDSA/pkg/zkSigma"
)

func main() {
	var secp256k1 curve.Group
	pBits := 3072
	qBits := 256
	schnorr, _ := group.GenerateSchnorrGroup(pBits, qBits)
	secp256k1 = curve.NewSecp256k1Group()
	//group/field,Z/Zq
	Zq, _ := gf.NewGF(schnorr.Q)
	//secp256k1 curve
	G1 := secp256k1.Gen()
	G2 := secp256k1.ScalarBaseMult(big.NewInt(2))
	//normal ElGamal
	t := 18
	n := 20
	PriKey, _ := nELGa.GenerateKey(qBits, 1-1/(4^qBits))
	// 		=== Trusted setup ===
	srs, err1 := kzg.NewTrustedSetup(t + 1)
	if err1 != nil {
		log.Fatalf("Failed to create trusted setup: %v", err1)
	}
	//=== 5.1(KGen)-PVSS.Share ===
	com, proof, x_ij, y_j, zkproof0, points0 := kGen.PVSS(srs, t, big.NewInt(int64(3)), PriKey, secp256k1, G1)
	//=== 5.1(KGen)-PVSS.Comb & Verification ===
	//proofs verification
	valid0 := zkSigma.VeriLElGEnc(secp256k1, points0, PriKey.P, y_j[0], y_j[1], zkproof0, []byte("zkproof0"))
	fmt.Printf("LElGamal.Enc() proof validation: %v\n", valid0)
	y_ji := make([]*big.Int, len(y_j)/2)
	for i := 0; i < len(y_ji); i++ {
		m_ji, _ := PriKey.Decrypt(y_j[i*2], y_j[i*2+1])
		y_j64, _ := strconv.ParseInt(string(m_ji), 10, 64)
		y_ji[i] = big.NewInt(y_j64)
	}
	proof7, points2 := zkSigma.GenLElGDecDL(secp256k1, G1, PriKey.P, y_j[0], y_j[1], secp256k1.ScalarBaseMult(y_ji[0]), PriKey.X, y_ji[0], []byte("proof7"))
	veriP := kzg.VerifyBatchProof(srs, com, proof, x_ij, y_ji)
	x, _ := kzg.LagrangeInterpolation(x_ij, y_ji)
	valid7 := zkSigma.VeriLElGDecDL(secp256k1, points2, y_j[1], proof7, []byte("proof7"))
	fmt.Printf("LElGamal.Dec() proof validation: %v\n", valid7)
	fmt.Printf("Proofs Verification Passed? %v\n", veriP)
	fmt.Printf("the interpolation of undetermined distributed value %d\n", x[0])
	// === 5.2-Offline BMtP ===
	triple1 := BMtP.OffBMtP(schnorr, t, n)
	triple2 := BMtP.OffBMtP(schnorr, t, n)
	fmt.Println(triple1.A, triple1.B, triple1.C)
	// === 5.3-Offline-Pre-signing ===
	r, ki, kx_i, e2, d2, proof1, betaG, proof2, H1, H2, proof3, H3, proof4, H4, proof5, R_i, C, proof6, S_i, points6 :=
		Sign.Pre_Sign(schnorr, Zq, secp256k1, G1, G2, srs, PriKey, x[0], triple1, triple2, t, n)
	valid1 := zkSigma.VeriProofSch(secp256k1, betaG, proof1, []byte("proof1"))
	valid2 := zkSigma.VeriDDLProof(secp256k1, G1, G2, H1, H2, proof2, []byte("proof2"))
	valid3 := zkSigma.VeriDDLProof(secp256k1, G1, G2, betaG, H3, proof3, []byte("proof3"))
	valid4 := zkSigma.VeriDDLProof(secp256k1, G1, G2, secp256k1.ScalarMult(G1, x[0]), H4, proof4, []byte("proof4"))
	valid5 := zkSigma.VeriDDLProof(secp256k1, G1, G2, H1, R_i, proof5, []byte("proof5"))
	valid6 := zkSigma.VeriPederDlProof(secp256k1, points6, G1, G2, H1, C, S_i, proof6, []byte("proof6"))
	fmt.Printf("DDL Proof1 validation: %v\n", valid1)
	fmt.Printf("DDL Proof2 validation: %v\n", valid2)
	fmt.Printf("DDL Proof3 validation: %v\n", valid3)
	fmt.Printf("DDL Proof4 validation: %v\n", valid4)
	fmt.Printf("DDL Proof4 validation: %v\n", valid5)
	fmt.Printf("Pedersen and Dlog proof validation: %v\n", valid6)
	////=== 5.4-Online-signature ===
	msg, _ := rand.Int(rand.Reader, secp256k1.Order())
	s := Sign.OnSign(secp256k1, Zq, G1, msg, r, ki, kx_i, e2, d2, x[0], big.NewInt(int64(t)), big.NewInt(int64(n)))
	fmt.Println("Threshold ECDSA output:(%v,%v)", r, s)
}
