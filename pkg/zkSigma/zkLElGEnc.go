package zkSigma

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"t_ECDSA/pkg/curve"
)

type ElGamalProof struct {
	A, B curve.Point
	Z    *big.Int
	W    *big.Int
}

func genChaLElGa(
	group curve.Group,
	points []curve.Point,
	msg []byte,
) *big.Int {
	H := sha256.New()

	// serialization
	for _, p := range points {
		sp := p.(curve.SPoint)
		H.Write(sp.X.Bytes())
		H.Write(sp.Y.Bytes())
	}

	H.Write(msg)

	hashBytes := H.Sum(nil)
	c := new(big.Int).SetBytes(hashBytes)
	return c.Mod(c, group.Order())
}

func GenLElGEnc(group curve.Group, G, H, C1, C2 curve.Point, x, r *big.Int, msg []byte) (*ElGamalProof, []curve.Point) {
	q := group.Order()

	t1, _ := rand.Int(rand.Reader, q)
	t2, _ := rand.Int(rand.Reader, q)

	// A = t1 * G
	A := group.ScalarBaseMult(t1)
	// B = α·G + β·H
	t1H := group.ScalarMult(H, t1)
	t2G := group.ScalarBaseMult(t2)
	B := group.Add(t1H, t2G)

	// c = H(G||H||C1||C2||A||B)
	points := []curve.Point{G, H, C1, C2, A, B}
	c := genChaLElGa(group, points, msg)
	// response z1 = t1 + c·r mod q
	z1 := new(big.Int).Mul(c, r)
	z1.Add(z1, t1)
	z1.Mod(z1, q)

	// z2 = t2 + c·x mod q
	z2 := new(big.Int).Mul(c, x)
	z2.Add(z2, t2)
	z2.Mod(z2, q)

	return &ElGamalProof{
		A: A,
		B: B,
		Z: z1,
		W: z2,
	}, points
}

func VeriLElGEnc(group curve.Group, points []curve.Point, H, C1, C2 curve.Point, proof *ElGamalProof, msg []byte) bool {

	c := genChaLElGa(group, points, msg)
	// Equation 1 verification：z1*G == A + c*C1
	left1 := group.ScalarBaseMult(proof.Z)
	right1 := group.ScalarMult(C1, c)
	right1 = group.Add(proof.A, right1)
	if !group.Equal(left1, right1) {
		fmt.Printf("the verification 1 failed")
		return false
	}

	// Equation 2 verification：z1*H + z2*G == B + c*C2
	left2 := group.ScalarMult(H, proof.Z)
	z2G := group.ScalarBaseMult(proof.W)
	left2 = group.Add(left2, z2G)

	right2 := group.ScalarMult(C2, c)
	right2 = group.Add(proof.B, right2)
	if !group.Equal(left2, right2) {
		fmt.Printf("the verification 2 failed,left%d,right%d\n", left2.(curve.SPoint).X, right2.(curve.SPoint).X)
		return false
	}
	return group.Equal(left2, right2)
}
