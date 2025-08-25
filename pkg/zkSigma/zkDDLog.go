package zkSigma

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"t_ECDSA/pkg/curve"
)

// DoubleDLProof 包含双离散对数证明的承诺和响应
type DoubleDLProof struct {
	R1 curve.Point // 承诺 R1 = g1^k
	R2 curve.Point // 承诺 R2 = g2^k
	Z  *big.Int    // 响应 z = k + c*x
}

// genChaDoubleDL 生成挑战 c = H(g1 || g2 || h1 || h2 || R1 || R2 || msg)
func genChaDoubleDL(secp256k1 curve.Group, g1, g2, h1, h2, R1, R2 curve.Point, msg []byte) *big.Int {
	h := sha256.New()

	// 序列化 g1
	h.Write(g1.(curve.SPoint).X.Bytes())
	h.Write(g1.(curve.SPoint).Y.Bytes())

	// 序列化 g2
	h.Write(g2.(curve.SPoint).X.Bytes())
	h.Write(g2.(curve.SPoint).Y.Bytes())

	// 序列化 h1
	h.Write(h1.(curve.SPoint).X.Bytes())
	h.Write(h1.(curve.SPoint).Y.Bytes())

	// 序列化 h2
	h.Write(h2.(curve.SPoint).X.Bytes())
	h.Write(h2.(curve.SPoint).Y.Bytes())

	// 序列化 R1
	h.Write(R1.(curve.SPoint).X.Bytes())
	h.Write(R1.(curve.SPoint).Y.Bytes())

	// 序列化 R2
	h.Write(R2.(curve.SPoint).X.Bytes())
	h.Write(R2.(curve.SPoint).Y.Bytes())

	// 添加消息
	h.Write(msg)

	hn := new(big.Int).SetBytes(h.Sum(nil))
	return new(big.Int).Mod(hn, secp256k1.Order())
}

// GenerateDoubleDLProof 生成双离散对数相等证明
func GenDDLProof(
	secp256k1 curve.Group,
	g1, g2, h1, h2 curve.Point, // 公共参数
	x *big.Int, // 秘密值 x (满足 h1 = g1^x, h2 = g2^x)
	msg []byte, // 绑定消息
) *DoubleDLProof {
	n := secp256k1.Order()

	// 1. 生成随机数 k
	k, _ := rand.Int(rand.Reader, n)

	// 2. 计算承诺 R1 = g1^k, R2 = g2^k
	R1 := secp256k1.ScalarMult(g1, k) // R1 = g1^k
	R2 := secp256k1.ScalarMult(g2, k) // R2 = g2^k

	// 3. 生成挑战 c = H(g1 || g2 || h1 || h2 || R1 || R2 || msg)
	c := genChaDoubleDL(secp256k1, g1, g2, h1, h2, R1, R2, msg)

	// 4. 计算响应 z = k + c*x mod n
	z := new(big.Int).Mul(c, x)
	z.Add(z, k).Mod(z, n)

	return &DoubleDLProof{R1: R1, R2: R2, Z: z}
}

// VerifyDoubleDLProof 验证双离散对数相等证明
func VeriDDLProof(
	secp256k1 curve.Group,
	g1, g2, h1, h2 curve.Point, // 公共参数
	proof *DoubleDLProof, // 证明 (R1, R2, z)
	msg []byte, // 绑定消息
) bool {
	// 1. 重新计算挑战 c
	c := genChaDoubleDL(secp256k1, g1, g2, h1, h2, proof.R1, proof.R2, msg)

	// 2. 计算 g1^z
	g1z := secp256k1.ScalarMult(g1, proof.Z) // g1^z

	// 3. 计算 R1 * h1^c
	h1c := secp256k1.ScalarMult(h1, c)    // h1^c
	R1h1c := secp256k1.Add(proof.R1, h1c) // R1 * h1^c

	// 4. 验证 g1^z == R1 * h1^c
	if !equalPoints(g1z, R1h1c) {
		fmt.Println("第一条验证失败")
		return false
	}

	// 5. 计算 g2^z
	g2z := secp256k1.ScalarMult(g2, proof.Z) // g2^z

	// 6. 计算 R2 * h2^c
	h2c := secp256k1.ScalarMult(h2, c)    // h2^c
	R2h2c := secp256k1.Add(proof.R2, h2c) // R2 * h2^c

	// 7. 验证 g2^z == R2 * h2^c
	if !equalPoints(g2z, R2h2c) {
		fmt.Println("第二条验证失败")
		return false
	}

	return true
}

// equalPoints 比较两个曲线点是否相等
func equalPoints(p1, p2 curve.Point) bool {
	sp1 := p1.(curve.SPoint)
	sp2 := p2.(curve.SPoint)
	fmt.Printf("p1.X:%d,p2.X:%d\n", sp1.X, sp2.X)
	return sp1.X.Cmp(sp2.X) == 0 && sp1.Y.Cmp(sp2.Y) == 0
}

// 示例使用
func ExampleDoubleDLProof(secp256k1 curve.Group) {
	// 初始化曲线
	n := secp256k1.Order()

	// 1. 生成公共参数
	g1 := secp256k1.Gen()                         // 第一个生成元
	g2 := secp256k1.ScalarBaseMult(big.NewInt(2)) // 第二个生成元 (示例)

	// 生成秘密 x
	x, _ := rand.Int(rand.Reader, n)

	// 计算 h1 = g1^x, h2 = g2^x
	h1 := secp256k1.ScalarMult(g1, x)
	h2 := secp256k1.ScalarMult(g2, x)

	// 2. 生成证明 (绑定到消息 "test")
	msg := []byte("Proof2")
	proof := GenDDLProof(secp256k1, g1, g2, h1, h2, x, msg)

	// 3. 验证证明
	valid := VeriDDLProof(secp256k1, g1, g2, h1, h2, proof, msg)
	fmt.Printf("双离散对数证明验证结果: %v\n", valid) // 输出 true
}
