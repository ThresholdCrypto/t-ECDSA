package zkSigma

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"t_ECDSA/pkg/curve"
)

// PedersenDlogProof 包含证明结构
type PedersenDlogProof struct {
	RC curve.Point // Pedersen 随机点: g^k * h^s
	RY curve.Point // Dlog 随机点: g^k
	Zx *big.Int    // x 的响应: k + c*x
	Zr *big.Int    // r 的响应: s + c*r
}

// GeneratePedersenDlogProof 生成证明
func GenPederDlProof(
	group curve.Group,
	g1, g2, h curve.Point, // Pedersen 生成元
	C curve.Point, // Pedersen 承诺: C = g^x * h^r
	y curve.Point, // Dlog 公开值: y = g^x
	x, r *big.Int, // 秘密值 (x 必须相同)
	msg []byte, // 绑定消息
) (*PedersenDlogProof, []curve.Point) {
	n := group.Order()

	// 1. 生成随机数 k (用于x), s (用于r)
	k, _ := rand.Int(rand.Reader, n)
	s, _ := rand.Int(rand.Reader, n)

	// 2. 计算承诺
	RC := group.Add( // RC = g1^k * h^s
		group.ScalarMult(g1, k),
		group.ScalarMult(h, s),
	)
	RY := group.ScalarMult(g2, k) // RY = g2^k
	points := []curve.Point{g1, h, g2, C, y, RC, RY}
	// 3. 生成挑战 c = H(g1 || h || g2 || C || y || RC || RY || msg)
	c := genChaPederDL(group, points, msg)

	// 4. 计算响应
	zx := new(big.Int).Mul(c, x)
	zx.Add(zx, k).Mod(zx, n) // zx = k + c*x

	zr := new(big.Int).Mul(c, r)
	zr.Add(zr, s).Mod(zr, n) // zr = s + c*r

	return &PedersenDlogProof{RC: RC, RY: RY, Zx: zx, Zr: zr}, points
}

// VerifyPedersenDlogProof 验证证明
func VeriPederDlProof(
	group curve.Group,
	points []curve.Point, // 公共参数
	G1, G2, H1, C, y curve.Point,
	proof *PedersenDlogProof, // 证明
	msg []byte, // 绑定消息
) bool {
	// 1. 重构挑战
	c := genChaPederDL(group, points, msg)

	// 2. 验证 Pedersen 部分: g^{zx} * h^{zr} == RC * C^c
	leftPed := group.Add(
		group.ScalarMult(G1, proof.Zx), // g^{zx}
		group.ScalarMult(H1, proof.Zr), // h^{zr}
	)
	rightPed := group.Add(
		proof.RC,               // RC
		group.ScalarMult(C, c), // C^c
	)
	if !group.Equal(leftPed, rightPed) {
		fmt.Println("Pedersen 部分验证失败")
		return false
	}

	// 3. 验证 Dlog 部分: g^{zx} == RY * y^c
	leftDlog := group.ScalarMult(G2, proof.Zx) // g^{zx}
	rightDlog := group.Add(
		proof.RY,               // RY
		group.ScalarMult(y, c), // y^c
	)
	if !group.Equal(leftDlog, rightDlog) {
		fmt.Println("离散对数部分验证失败")
		return false
	}

	// 4. 验证值一致性（隐含在等式中）
	return true
}

// genChallenge 生成挑战 c
func genChaPederDL(
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
