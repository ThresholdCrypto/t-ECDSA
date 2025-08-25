package zkSigma

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"t_ECDSA/pkg/curve"
)

// PedersenDlogProof struct
type PedersenDlogProof struct {
	RC curve.Point // Pedersen: g^k * h^s
	RY curve.Point // Dlog: g^k
	Zx *big.Int    // response: k + c*x
	Zr *big.Int    // response: s + c*r
}

// GeneratePedersenDlogProof
func GenPederDlProof(
	group curve.Group,
	g1, g2, h curve.Point, // Pedersen generator
	C curve.Point,         // Pedersen commitment: C = g^x * h^r
	y curve.Point,         // Dlog public value: y = g^x
	x, r *big.Int,         // Secret value
	msg []byte,
) (*PedersenDlogProof, []curve.Point) {
	n := group.Order()

	//1. Generate random numbers k (for x) and s (for r)
	k, _ := rand.Int(rand.Reader, n)
	s, _ := rand.Int(rand.Reader, n)

	//2. Compute commitment
	RC := group.Add( // RC = g1^k * h^s
		group.ScalarMult(g1, k),
		group.ScalarMult(h, s),
	)
	RY := group.ScalarMult(g2, k) // RY = g2^k
	points := []curve.Point{g1, h, g2, C, y, RC, RY}
	//3. c = H(g1 || h || g2 || C || y || RC || RY || msg)
	c := genChaPederDL(group, points, msg)

	// 4. Compute response
	zx := new(big.Int).Mul(c, x)
	zx.Add(zx, k).Mod(zx, n) // zx = k + c*x

	zr := new(big.Int).Mul(c, r)
	zr.Add(zr, s).Mod(zr, n) // zr = s + c*r

	return &PedersenDlogProof{RC: RC, RY: RY, Zx: zx, Zr: zr}, points
}

// VerifyPedersenDlogProof
func VeriPederDlProof(
	group curve.Group,
	points []curve.Point,
	G1, G2, H1, C, y curve.Point,
	proof *PedersenDlogProof,
	msg []byte,
) bool {
	c := genChaPederDL(group, points, msg)

	// 2. Verify: g^{zx} * h^{zr} == RC * C^c
	leftPed := group.Add(
		group.ScalarMult(G1, proof.Zx), // g^{zx}
		group.ScalarMult(H1, proof.Zr), // h^{zr}
	)
	rightPed := group.Add(
		proof.RC,               // RC
		group.ScalarMult(C, c), // C^c
	)
	if !group.Equal(leftPed, rightPed) {
		fmt.Println("Pedersen Partial Verification Failed")
		return false
	}

	// 3. Verify Dlog: g^{zx} == RY * y^c
	leftDlog := group.ScalarMult(G2, proof.Zx) // g^{zx}
	rightDlog := group.Add(
		proof.RY,               // RY
		group.ScalarMult(y, c), // y^c
	)
	if !group.Equal(leftDlog, rightDlog) {
		fmt.Println("Discrete Logarithm Partial Verification Failed")
		return false
	}

	return true
}

// genChallenge
func genChaPederDL(
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
