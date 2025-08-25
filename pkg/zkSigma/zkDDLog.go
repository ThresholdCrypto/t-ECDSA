package zkSigma

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"t_ECDSA/pkg/curve"
)

// DoubleDLProof double discrete logarithm proof
type DoubleDLProof struct {
	R1 curve.Point // commitment R1 = g1^k
	R2 curve.Point // commitment R2 = g2^k
	Z  *big.Int    // commitment z = k + c*x
}

// genChaDoubleDL: challenge c = H(g1 || g2 || h1 || h2 || R1 || R2 || msg)
func genChaDoubleDL(secp256k1 curve.Group, g1, g2, h1, h2, R1, R2 curve.Point, msg []byte) *big.Int {
	h := sha256.New()

	// serialization g1
	h.Write(g1.(curve.SPoint).X.Bytes())
	h.Write(g1.(curve.SPoint).Y.Bytes())

	h.Write(g2.(curve.SPoint).X.Bytes())
	h.Write(g2.(curve.SPoint).Y.Bytes())

	h.Write(h1.(curve.SPoint).X.Bytes())
	h.Write(h1.(curve.SPoint).Y.Bytes())

	h.Write(h2.(curve.SPoint).X.Bytes())
	h.Write(h2.(curve.SPoint).Y.Bytes())

	h.Write(R1.(curve.SPoint).X.Bytes())
	h.Write(R1.(curve.SPoint).Y.Bytes())

	h.Write(R2.(curve.SPoint).X.Bytes())
	h.Write(R2.(curve.SPoint).Y.Bytes())

	h.Write(msg)

	hn := new(big.Int).SetBytes(h.Sum(nil))
	return new(big.Int).Mod(hn, secp256k1.Order())
}

// GenerateDoubleDLProof
func GenDDLProof(
	secp256k1 curve.Group,
	g1, g2, h1, h2 curve.Point,
	x *big.Int, // (h1 = g1^x, h2 = g2^x)
	msg []byte,
) *DoubleDLProof {
	n := secp256k1.Order()

	// 1. randomly sample k
	k, _ := rand.Int(rand.Reader, n)

	// 2. commitment R1 = g1^k, R2 = g2^k
	R1 := secp256k1.ScalarMult(g1, k) // R1 = g1^k
	R2 := secp256k1.ScalarMult(g2, k) // R2 = g2^k

	// 3. challenge c = H(g1 || g2 || h1 || h2 || R1 || R2 || msg)
	c := genChaDoubleDL(secp256k1, g1, g2, h1, h2, R1, R2, msg)

	// 4. response z = k + c*x mod n
	z := new(big.Int).Mul(c, x)
	z.Add(z, k).Mod(z, n)

	return &DoubleDLProof{R1: R1, R2: R2, Z: z}
}

// VerifyDoubleDLProof
func VeriDDLProof(
	secp256k1 curve.Group,
	g1, g2, h1, h2 curve.Point,
	proof *DoubleDLProof, // (R1, R2, z)
	msg []byte,
) bool {
	// 1. re-comptue challenge c
	c := genChaDoubleDL(secp256k1, g1, g2, h1, h2, proof.R1, proof.R2, msg)

	// 2. recover g1^z
	g1z := secp256k1.ScalarMult(g1, proof.Z) // g1^z

	// 3. R1 * h1^c
	h1c := secp256k1.ScalarMult(h1, c)    // h1^c
	R1h1c := secp256k1.Add(proof.R1, h1c) // R1 * h1^c

	// 4. verify g1^z == R1 * h1^c
	if !equalPoints(g1z, R1h1c) {
		fmt.Println("Equation 1 verification failed")
		return false
	}

	// 5. g2^z
	g2z := secp256k1.ScalarMult(g2, proof.Z) // g2^z

	// 6. R2 * h2^c
	h2c := secp256k1.ScalarMult(h2, c)    // h2^c
	R2h2c := secp256k1.Add(proof.R2, h2c) // R2 * h2^c

	// 7. Verify g2^z == R2 * h2^c
	if !equalPoints(g2z, R2h2c) {
		fmt.Println("Equation 2 verification failed")
		return false
	}

	return true
}

// equalPoints
func equalPoints(p1, p2 curve.Point) bool {
	sp1 := p1.(curve.SPoint)
	sp2 := p2.(curve.SPoint)
	fmt.Printf("p1.X:%d,p2.X:%d\n", sp1.X, sp2.X)
	return sp1.X.Cmp(sp2.X) == 0 && sp1.Y.Cmp(sp2.Y) == 0
}

func ExampleDoubleDLProof(secp256k1 curve.Group) {
	n := secp256k1.Order()

	g1 := secp256k1.Gen()
	g2 := secp256k1.ScalarBaseMult(big.NewInt(2))

	x, _ := rand.Int(rand.Reader, n)

	// 1. h1 = g1^x, h2 = g2^x
	h1 := secp256k1.ScalarMult(g1, x)
	h2 := secp256k1.ScalarMult(g2, x)

	// 2. Bound Message
	msg := []byte("Proof2")
	proof := GenDDLProof(secp256k1, g1, g2, h1, h2, x, msg)

	// 3. Verifying
	valid := VeriDDLProof(secp256k1, g1, g2, h1, h2, proof, msg)
	fmt.Printf("Validation: %v\n", valid) // true
}
