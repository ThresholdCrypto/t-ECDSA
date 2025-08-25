package BMtP

import (
	"bytes"
	"crypto/rand"
	"fmt"
	kzg "github.com/arnaucube/kzg-commitments-study"
	"github.com/lavode/secret-sharing/gf"
	"math/big"
	"t_ECDSA/internal/ElGamal"
	"t_ECDSA/pkg/group"
	"time"
)

type BeaverTriple struct {
	A *big.Int // a
	B *big.Int // b
	C *big.Int // c = a*b
}

// triples, _ := GenerateTriples(params, 3, 5) // 3-out-of-5共享
func GenerateTriples(schG group.SchnorrGroup, t, n int) ([]BeaverTriple, error) {
	triples := make([]BeaverTriple, n)

	// 1. 随机生成多项式系数
	coeffA := make([]*big.Int, t)
	coeffB := make([]*big.Int, t)
	for i := range coeffA {
		coeffA[i], _ = rand.Int(rand.Reader, schG.Q)
		coeffB[i], _ = rand.Int(rand.Reader, schG.Q)
	}

	// 2. 为每个参与者计算份额
	for i := 1; i <= n; i++ {
		x := big.NewInt(int64(i))
		a := evalPoly(coeffA, x, schG.Q)
		b := evalPoly(coeffB, x, schG.Q)
		c := new(big.Int).Mul(a, b)
		c.Mod(c, schG.Q)

		triples[i-1] = BeaverTriple{a, b, c}
	}
	return triples, nil
}

// evalPoly(mod q)
func evalPoly(coeffs []*big.Int, x, q *big.Int) *big.Int {
	res := new(big.Int)
	xi := big.NewInt(1) // x^0
	for _, c := range coeffs {
		term := new(big.Int).Mul(c, xi)
		res.Add(res, term)
		res.Mod(res, q)
		xi.Mul(xi, x).Mod(xi, q)
	}
	return res
}

// Compute global value e,d
func OnBMtP1(Zq gf.GF, xShare, yShare *big.Int, triple BeaverTriple) (*big.Int, *big.Int) {
	// 1. 计算e = x - a 和 d = y - b
	ei := new(big.Int).Sub(xShare, triple.A)
	ei.Mod(ei, Zq.P)
	di := new(big.Int).Sub(yShare, triple.B)
	di.Mod(di, Zq.P)
	//e1_1.Sub(ki[0],triple1.A)
	//d1_1.Sub(beta_i,triple1.B)
	//e2_1.Sub(ki[0],triple2.A)
	//d2_1.Sub(xi,triple2.B)
	return ei, di
}
func OnBMtP2(Zq gf.GF, pi, ei, di []*big.Int, triple BeaverTriple) *big.Int {
	// 1. robustness for e & d
	e, _ := kzg.LagrangeInterpolation(pi, ei)
	d, _ := kzg.LagrangeInterpolation(pi, di)
	fmt.Printf("Interpolation distributed value e:%d,d:%d\n", e[0], d[0])
	// 3. 计算最终共享: ci + e*b + a*d + e*d
	term1 := new(big.Int).Mul(e[0], triple.B)
	term2 := new(big.Int).Mul(triple.A, d[0])
	term3 := new(big.Int).Mul(e[0], d[0])
	result := new(big.Int).Add(triple.C, term1)
	result.Add(result, term2)
	result.Add(result, term3)
	result.Mod(result, Zq.P)
	return result
}
func OffBMtP(schG group.SchnorrGroup, t, n int) BeaverTriple {
	a_i := big.NewInt(int64(1))
	b_i := big.NewInt(int64(1))
	c_i := new(big.Int)
	b := big.NewInt(int64(12))
	// === 0-t_ElGamal KeyGen ===
	pub, _, privShares, err := ElGamal.KeyGen(schG, t, n)
	if err != nil {
		fmt.Printf("Key generation failed: %v\n", err)
	}
	fmt.Printf("Public key:\n\tP = %d\n\tQ = %d\n\tg = %d\n\tY= %d\n", pub.P, pub.Q, pub.G, pub.Y)
	fmt.Println("Private key shares:")
	for _, share := range privShares {
		fmt.Printf("\t Share %d = %d\n", share.ID, share.Value)
		fmt.Println("\n---------------\n")
	}
	// === 1-BMtP.Gen ===/=== 2-BMtP.cal1(a_i*b) ===
	start1 := time.Now()
	c_i.Mul(a_i, b)
	msg := make([]byte, 64)
	copy(msg, c_i.Bytes())
	ctxt, err := ElGamal.Enc(pub, msg)
	if err != nil {
		fmt.Printf("Encryption failed: %v\n", err)
	}
	fmt.Printf("plaintext: 0x%x\n", msg)
	fmt.Printf("Message encrypted:\n\tR = %d\n\tC = 0x%x\n", ctxt.R, ctxt.C)
	fmt.Println("\n---------------\n")
	elapsed1 := time.Since(start1)
	fmt.Printf("BMtP.Gen程序总运行时间: %s\n", elapsed1)
	// === 3-BMtP.cal2(c_i) ===
	start2 := time.Now()
	decryptionShares := make([]ElGamal.DecryptionShare, t+1)
	for i := 0; i < t+1; i++ {
		share, err := ElGamal.Dec(pub, privShares[i], ctxt)
		if err != nil {
			fmt.Printf("Decryption share generation failed: %v\n", err)
		}
		decryptionShares[i] = share
	}
	fmt.Println("Decryption shares:")
	for _, share := range decryptionShares {
		fmt.Printf("\t Share %d = %d\n", share.ID, share.Value)
	}
	fmt.Println("\n---------------\n")
	elapsed2 := time.Since(start2)
	fmt.Printf("BMtP.cal2-PDec程序总运行时间: %s\n", elapsed2)
	// === Output-Recover ===
	start3 := time.Now()
	re_M, err := ElGamal.Recover(pub, decryptionShares, ctxt)
	if err != nil {
		fmt.Printf("Message recovery failed: %v\n", err)
	}
	fmt.Printf("Recovered message: 0x%x\n", re_M)
	if bytes.Equal(re_M, msg) {
		fmt.Println("Recovered == Message")
	} else {
		fmt.Println("Recovered != Message")
	}
	//trimmed := bytes.TrimRight(recoM, "\x00")
	//rci, _ := strconv.Atoi(string(trimmed))
	re_ci := new(big.Int).SetBytes(re_M)
	triple := BeaverTriple{a_i, b_i, re_ci}
	elapsed3 := time.Since(start3)
	fmt.Printf("BMtP.cal2-Recover程序总运行时间: %s\n", elapsed3)
	return triple
}
