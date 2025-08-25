package zkSigma

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"t_ECDSA/pkg/curve"
)

type ConsistencyProof struct {
	A1, A2, A3 curve.Point // commitments
	Z1, Z2     *big.Int    // response
}

func GenLElGDecDL(
	group curve.Group,
	G, PK, C1, C2, X curve.Point,
	sk, m *big.Int,
	msg []byte,
) (*ConsistencyProof, []curve.Point) {
	q := group.Order()

	r1, _ := rand.Int(rand.Reader, q)
	r2, _ := rand.Int(rand.Reader, q)

	// A1 = r1 * G (PK relationship)
	A1 := group.ScalarBaseMult(r1)

	// A2 = r2 * G (X relationship)
	A2 := group.ScalarBaseMult(r2)

	// A3 = r1 * C1 + r2 * PK (decryption relationship)
	r1C1 := group.ScalarMult(C1, r1)
	r2PK := group.ScalarMult(PK, r2)
	A3 := group.Add(r1C1, r2PK)

	// A4 = m * PK
	A4 := group.ScalarMult(PK, m)
	points := []curve.Point{G, PK, C1, C2, X, A1, A2, A3, A4}
	c := genChaLElGa(group, points, msg)

	// Z1 = r1 + c * sk mod q
	Z1 := new(big.Int).Mul(c, sk)
	Z1.Add(Z1, r1)
	Z1.Mod(Z1, q)

	// Z2 = r2 + c * m mod q
	Z2 := new(big.Int).Mul(c, m)
	Z2.Add(Z2, r2)
	Z2.Mod(Z2, q)

	return &ConsistencyProof{
		A1: A1,
		A2: A2,
		A3: A3,
		Z1: Z1,
		Z2: Z2,
	}, points
}

func VeriLElGDecDL(
	group curve.Group,
	points []curve.Point, //[G, PK, C1, C2, X, A1, A2, A3]
	C2 curve.Point, //
	proof *ConsistencyProof,
	msg []byte,
) bool {
	PK := points[1]
	C1 := points[2]
	// C2 := points[3]
	X := points[4]
	A1 := points[5]
	A2 := points[6]
	A3 := points[7]
	A4 := points[8]

	c := genChaLElGa(group, points, msg)

	// 1. Verify PK: Z1*G = A1 + c*PK
	left1 := group.ScalarBaseMult(proof.Z1)
	right1 := group.ScalarMult(PK, c)
	right1 = group.Add(A1, right1)
	if !group.Equal(left1, right1) {
		fmt.Println("PK relation verification failed")
		return false
	}

	// 2. Verify x: Z2*G = A2 + c*X
	left2 := group.ScalarBaseMult(proof.Z2)
	right2 := group.ScalarMult(X, c)
	right2 = group.Add(A2, right2)
	if !group.Equal(left2, right2) {
		fmt.Println("X relation verification failed")
		return false
	}

	// 3. Verify decryption: Z1*C1 + Z2*PK = A3 + c*(C2 - X)
	// left: Z1*C1 + Z2*PK
	left3 := group.ScalarMult(C1, proof.Z1)
	Z2PK := group.ScalarMult(PK, proof.Z2)
	cX := group.ScalarMult(X, c)
	left3 = group.Add(left3, Z2PK)
	left3 = group.Add(left3, cX)

	// right: A3 + c*(C2 - X) + A4
	cC2 := group.ScalarMult(C2, c)
	cA4 := group.ScalarMult(A4, c)
	right3 := group.Add(A3, cC2)
	right3 = group.Add(right3, cA4)

	if !group.Equal(left3, right3) {
		fmt.Printf("Decryption relation verification failed left:%d,right:%d\n", left3.(curve.SPoint).X, right3.(curve.SPoint).X)
		return false
	}
	return true
}
