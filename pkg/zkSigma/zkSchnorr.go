package zkSigma

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"t_ECDSA/pkg/curve"
)

// SchnorrProof 包含证明的承诺和响应
type SchnorrProof struct {
	R curve.Point // 承诺 R = kG
	Z *big.Int    // 响应 z = k + c*x
}

// generateChallenge 生成挑战 c = H(Q || R || msg)
func genChaSch(secp256k1 curve.Group, PK curve.Point, R curve.Point, msg []byte) *big.Int {
	h := sha256.New()
	h.Write(PK.(curve.SPoint).X.Bytes())
	h.Write(PK.(curve.SPoint).Y.Bytes())
	h.Write(R.(curve.SPoint).X.Bytes())
	h.Write(R.(curve.SPoint).Y.Bytes())
	h.Write(msg)
	hn := new(big.Int).SetBytes(h.Sum(nil))
	return new(big.Int).Mod(hn, secp256k1.Order())
}

// GenerateProof 生成 Schnorr 证明
func GenProofSch(secp256k1 curve.Group, x *big.Int, PK curve.Point, msg []byte) *SchnorrProof {
	// 1. 生成随机数 k
	k, _ := rand.Int(rand.Reader, secp256k1.Order())
	R := secp256k1.ScalarBaseMult(k) // R = kG

	// 2. 生成挑战 c = H(Q || R || msg)
	c := genChaSch(secp256k1, PK, R, msg)

	// 3. 计算响应 z = k + c*x mod n
	z := new(big.Int).Mul(c, x)
	z.Add(z, k).Mod(z, secp256k1.Order())

	return &SchnorrProof{R: R, Z: z}
}

// VerifyProof 验证 Schnorr 证明
func VeriProofSch(secp256k1 curve.Group, PK curve.Point, proof *SchnorrProof, msg []byte) bool {
	// 1. 重新计算挑战 c
	c := genChaSch(secp256k1, PK, proof.R, msg)

	// 2. 计算 zG 和 R + cQ
	zG := secp256k1.ScalarBaseMult(proof.Z) // zG
	cQ := secp256k1.ScalarMult(PK, c)       // cQ
	R_CQ := secp256k1.Add(proof.R, cQ)      // R + cQ

	fmt.Printf("zG.X:%d,cQ.X:%d\n", zG.(curve.SPoint).X, R_CQ.(curve.SPoint).X)
	// 3. 验证 zG == R + cQ
	return zG.(curve.SPoint).X.Cmp(R_CQ.(curve.SPoint).X) == 0 && zG.(curve.SPoint).Y.Cmp(R_CQ.(curve.SPoint).Y) == 0
}
