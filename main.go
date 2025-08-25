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
	"t_ECDSA/pkg/utils"
	"t_ECDSA/pkg/zkSigma"
	"time"
)

func main() {

	pBits := 3072 //3072
	qBits := 256  //256
	//group/field,Z/Zq
	schnorr, _ := group.GenerateSchnorrGroup(pBits, qBits)
	var secp256k1 curve.Group
	secp256k1 = curve.NewSecp256k1Group()
	start := time.Now()
	Zq, _ := gf.NewGF(schnorr.Q)
	//secp256k1 curve
	G1 := secp256k1.Gen()
	G2 := secp256k1.ScalarBaseMult(big.NewInt(2))
	//normal ElGamal
	t := 2
	n := 3
	PriKey, _ := nELGa.GenerateKey(qBits, 1-1/(4^qBits))
	// 		=== Trusted setup ===
	srs, err1 := kzg.NewTrustedSetup(t + 1)
	if err1 != nil {
		log.Fatalf("Failed to create trusted setup: %v", err1)
	}
	start_offA := time.Now()
	Com1 := utils.CalComm(PriKey.P) + 64
	//=== 1-PVSS.Share(KGen) ===
	com, proof, x_ij, y_j := kGen.PVSS(srs, t, big.NewInt(int64(3)), PriKey)
	Com2 := 32 + 32*n + (n-1)*len(y_j[0]) + 64
	//=== 2-PVSS.Comb & Verification ===
	y_ji := make([]*big.Int, len(y_j)/2)
	for i := 0; i < len(y_ji); i++ {
		m_ji, _ := PriKey.Decrypt(y_j[i*2], y_j[i*2+1])
		y_j64, _ := strconv.ParseInt(string(m_ji), 10, 64)
		y_ji[i] = big.NewInt(y_j64)
	}
	veriP := kzg.VerifyBatchProof(srs, com, proof, x_ij, y_ji)
	x, _ := kzg.LagrangeInterpolation(x_ij, y_ji)
	fmt.Printf("Verification Passed? %v\n", veriP)
	fmt.Printf("Interpolation distributed value %d\n", x[0])
	xi := big.NewInt(int64(3))
	Q := secp256k1.ScalarMult(G1, xi)
	elapsed_offA := time.Since(start_offA)
	// === 3-Offline-Presignature(BMtP) ===
	start_offB := time.Now()
	triple1 := BMtP.OffBMtP(schnorr, t, n)
	elapsed_offB := time.Since(start_offB)
	triple2 := BMtP.OffBMtP(schnorr, t, n)
	fmt.Println(triple1.A, triple1.B, triple1.C)
	Com3 := (64 + 32*2 + 64 + 64 + 97*(n-1) + 64*(n-1)) * 2
	//    === 3-Offline-Presignature ===
	r, ki, kx_i, e2, d2, proof1, betaG, proof2, H1, H2 := Sign.Pre_Sign(schnorr, Zq, secp256k1, G1, G2, srs, PriKey, xi, triple1, triple2, t)
	valid1 := zkSigma.VeriProofSch(secp256k1, betaG, proof1, []byte("proof1"))
	valid2 := zkSigma.VeriDDLProof(secp256k1, G1, G2, H1, H2, proof2, []byte("proof2"))
	Com4 := 32 + 64 + Com1 + Com2 + 3*97 + 32*4 + 32 + 97*2 + 32*2
	fmt.Printf("Proof1 valid: %v\n", valid1)
	fmt.Printf("Proof1 valid: %v\n", valid2)
	//proof4: zk-Pedersen & DLog
	r1, _ := rand.Int(rand.Reader, secp256k1.Order())
	C := secp256k1.Add(
		secp256k1.ScalarMult(G1, xi),
		secp256k1.ScalarMult(H1, r1),
	)
	y := secp256k1.ScalarMult(G2, xi)
	msg1 := []byte("proof4")
	proof4, points := zkSigma.GenPederDlProof(secp256k1, G1, G2, H1, C, y, xi, r1, msg1)
	//proof5: zk-Lifted Elgamal Encryption
	sk, _ := rand.Int(rand.Reader, secp256k1.Order()) // 私钥
	pk := secp256k1.ScalarBaseMult(sk)                // 公钥 pk = sk·G
	C1 := secp256k1.ScalarBaseMult(r1)                // C1 = r·G
	xG := secp256k1.ScalarBaseMult(xi)                // x·G
	rH := secp256k1.ScalarMult(pk, r1)                // r·pk
	C2 := secp256k1.Add(xG, rH)                       // C2 = x·G + r·H
	proof5, points1 := zkSigma.GenLElGEnc(secp256k1, G1, pk, C1, C2, xi, r1, []byte("proof5"))
	//proof6: zk-Elgamal Decryption with DLog
	proof6, points2 := zkSigma.GenLElGDecDL(secp256k1, G1, pk, C1, C2, xG, sk, xi, []byte("proof6"))
	//proof7: zk-Elgamal Part Decryption-DDL

	////=== 4-Online-signature(NIZK) ===
	start_onS := time.Now()
	msg := big.NewInt(int64(2))
	s := Sign.On_Sign(Zq, G1, msg, r, ki, kx_i, e2, d2)
	fmt.Printf("Signature s:%d\n", s)
	//k := big.NewInt(int64(2))
	//Inverk := new(big.Int).ModInverse(k, secp256k1.Order())
	//InverkG := secp256k1.ScalarMult(G, Inverk)
	//r_x := new(big.Int).Mod(InverkG.(curve.SPoint).X, secp256k1.Order())
	//
	//s2 := new(big.Int).Mul(xi, r_x)
	//s3 := new(big.Int).Add(s2, msg)
	////s3M := new(big.Int).Mod(s3, Zq.P)
	//s1 := new(big.Int).Mul(k, s3)
	//sM := new(big.Int).Mod(s1, secp256k1.Order())
	InverS := new(big.Int).ModInverse(s, secp256k1.Order())
	u1 := new(big.Int).Mul(InverS, msg)
	u2 := new(big.Int).Mul(InverS, r)
	u11 := new(big.Int).Mod(u1, secp256k1.Order())
	u22 := new(big.Int).Mod(u2, secp256k1.Order())
	R := secp256k1.ScalarMult(G1, u11)
	rQ := secp256k1.ScalarMult(Q, u22)
	Pi := secp256k1.Add(R, rQ)
	ModVeri := new(big.Int).Mod(Pi.(curve.SPoint).X, secp256k1.Order())
	fmt.Printf("Left Verify:%d,Right Verify:%d\n", ModVeri, r)
	Com5 := 32 * 2
	//proofs verification
	valid4 := zkSigma.VeriPederDlProof(secp256k1, points, G1, G2, H1, C, y, proof4, msg1)
	fmt.Printf("Pedersen与Dlog秘密一致性证明验证结果: %v\n", valid4)
	valid5 := zkSigma.VeriLElGEnc(secp256k1, points1, pk, C1, C2, proof5, []byte("proof5"))
	fmt.Printf("LElGamal_Enc秘密一致性证明验证结果: %v\n", valid5)
	valid6 := zkSigma.VeriLElGDecDL(secp256k1, points2, C2, proof6, []byte("proof6"))
	fmt.Printf("LElGamal_Dec秘密一致性证明验证结果: %v\n", valid6)
	elapsed_onS := time.Since(start_onS)
	fmt.Printf("KeyGen程序总运行时间: %s\n", elapsed_offA)
	fmt.Printf("Offline-BMtP程序总运行时间: %s\n", elapsed_offB)
	fmt.Printf("online程序总运行时间: %s\n", elapsed_onS)
	elapsed := time.Since(start)
	fmt.Printf("all程序总通信开销: %v\n", (Com1 + Com2 + Com3 + Com4 + Com5))
	fmt.Printf("all程序总运行时间: %s\n", elapsed)
}
