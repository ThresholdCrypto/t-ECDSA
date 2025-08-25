package zkSigma

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"t_ECDSA/pkg/curve"
)

// 证明结构体
type ElGamalProof struct {
	A, B curve.Point // 承诺点A,B
	Z    *big.Int    // 响应值z (用于x)
	W    *big.Int    // 响应值w (用于r)
}

func genChaLElGa(
	group curve.Group,
	points []curve.Point,
	msg []byte,
) *big.Int {
	H := sha256.New()

	// 序列化所有点
	for _, p := range points {
		sp := p.(curve.SPoint)
		H.Write(sp.X.Bytes())
		H.Write(sp.Y.Bytes())
	}

	// 添加消息
	H.Write(msg)

	// 生成挑战
	hashBytes := H.Sum(nil)
	c := new(big.Int).SetBytes(hashBytes)
	return c.Mod(c, group.Order())
}

// 生成Lifted ElGamal正确性证明
func GenLElGEnc(group curve.Group, G, H, C1, C2 curve.Point, x, r *big.Int, msg []byte) (*ElGamalProof, []curve.Point) {
	q := group.Order()

	// 随机选择承诺随机数
	t1, _ := rand.Int(rand.Reader, q)
	t2, _ := rand.Int(rand.Reader, q)

	// 计算承诺点
	// A = t1 * G
	A := group.ScalarBaseMult(t1)
	// B = α·G + β·H
	t1H := group.ScalarMult(H, t1)
	t2G := group.ScalarBaseMult(t2)
	B := group.Add(t1H, t2G)

	// 计算挑战哈希 c = H(G||H||C1||C2||A||B)
	points := []curve.Point{G, H, C1, C2, A, B}
	c := genChaLElGa(group, points, msg)
	// 计算响应值 z1 = t1 + c·r mod q
	z1 := new(big.Int).Mul(c, r)
	z1.Add(z1, t1)
	z1.Mod(z1, q)

	// 计算响应值 z2 = t2 + c·x mod q
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

// 验证Lifted ElGamal正确性证明
func VeriLElGEnc(group curve.Group, points []curve.Point, H, C1, C2 curve.Point, proof *ElGamalProof, msg []byte) bool {

	// 计算挑战哈希 (与证明生成相同)
	c := genChaLElGa(group, points, msg)
	// 验证第一方程：z1*G == A + c*C1
	left1 := group.ScalarBaseMult(proof.Z)
	right1 := group.ScalarMult(C1, c)
	right1 = group.Add(proof.A, right1)
	if !group.Equal(left1, right1) {
		fmt.Printf("the verification 1 failed")
		return false
	}

	// 验证第二方程：z1*H + z2*G == B + c*C2
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
