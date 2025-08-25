package Sign

import (
	"crypto/rand"
	"fmt"
	"github.com/arnaucube/cryptofun/ecc"
	EcElGa "github.com/arnaucube/cryptofun/elgamal"
	kzg "github.com/arnaucube/kzg-commitments-study"
	"github.com/lavode/secret-sharing/gf"
	NeELGa "github.com/mirzazhar/elgamal"
	"math/big"
	"strconv"
	"t_ECDSA/cmd/kGen"
	"t_ECDSA/internal/BMtP"
	"t_ECDSA/pkg/curve"
	"t_ECDSA/pkg/group"
	"t_ECDSA/pkg/utils"
	"t_ECDSA/pkg/zkSigma"
)

func EC_Elgamal1() {
	// define new elliptic curve
	ec := ecc.NewEC(big.NewInt(int64(1)), big.NewInt(int64(18)), big.NewInt(int64(19)))

	// define new point
	g := ecc.Point{big.NewInt(int64(7)), big.NewInt(int64(11))}

	// define new ElGamal crypto system with the elliptic curve and the point
	eg, err := EcElGa.NewEG(ec, g)
	if err != nil {
		fmt.Println(err)
	}

	// define privK&pubK over the elliptic curve
	privK := big.NewInt(int64(5))
	pubK, err := eg.PubK(privK)
	if err != nil {
		fmt.Println(err)
	}

	// define point to encrypt
	m := ecc.Point{big.NewInt(int64(11)), big.NewInt(int64(12))}
	fmt.Println(m)
	// encrypt
	c, err := eg.Encrypt(m, pubK, big.NewInt(int64(15)))
	fmt.Println(c)
	if err != nil {
		fmt.Println(err)
	}
	// decrypt
	d, err := eg.Decrypt(c, privK)
	fmt.Println(d)
	if err != nil {
		fmt.Println(err)
	}
	// check that decryption is correct
	if !m.Equal(d) {
		fmt.Println("decrypted not equal to original")
	}
}
func EC_Elgamal2() {
	PriKey, err := NeELGa.GenerateKey(1024, 1-1/(4^1024))
	if err != nil {
		fmt.Println("Key Gen suc")
	}
	c1, c2, _ := PriKey.PublicKey.Encrypt([]byte("3"))
	m, _ := PriKey.Decrypt(c1, c2)
	fmt.Println(string(m))
}

func Pre_Sign(schG group.SchnorrGroup, Zq gf.GF, secp256k1 curve.Group, G1, G2 curve.Point,
	srs *kzg.TrustedSetup, PriKey *NeELGa.PrivateKey, xi *big.Int, triple1, triple2 BMtP.BeaverTriple, t, n int) (*big.Int,
	*big.Int, *big.Int, *big.Int, *big.Int, *zkSigma.SchnorrProof, curve.Point, *zkSigma.DoubleDLProof, curve.Point, curve.Point,
	*zkSigma.DoubleDLProof, curve.Point, *zkSigma.DoubleDLProof, curve.Point, *zkSigma.DoubleDLProof, curve.Point, curve.Point,
	*zkSigma.PedersenDlogProof, curve.Point, []curve.Point) {

	//=== 1-Offline-Presignature(Round 1-beta*G) ===
	p_i := make([]*big.Int, n)
	for i := 1; i <= n; i++ {
		p_i[i-1] = big.NewInt(int64(i))
	}
	k_i, _ := rand.Int(rand.Reader, secp256k1.Order())
	beta_i, _ := utils.RandomZq(schG.Q)
	fmt.Printf("randomly sample value %d from Z/Z_%d\n", Zq.P, beta_i)
	beta_G := secp256k1.ScalarMult(G1, beta_i)
	beta_rx := beta_G.(curve.SPoint).X
	beta_ry := beta_G.(curve.SPoint).Y
	fmt.Printf("r_x:%d\n", beta_rx)
	fmt.Printf("r_y:%d\n", beta_ry)
	// the proof of Schnorr for beta_i
	proof1 := zkSigma.GenProofSch(secp256k1, beta_i, beta_G, []byte("proof1"))
	//=== 2-Offline-Presignature(Round 2a-k_i(undermined value)) ===
	com_k, proof_k, xij_k, yj_k, proof0, points0 := kGen.PVSS(srs, t, k_i, PriKey, secp256k1, G1)
	yji_k := make([]*big.Int, len(yj_k)/2)
	for i := 0; i < len(yji_k); i++ {
		m_ji, _ := PriKey.Decrypt(yj_k[i*2], yj_k[i*2+1])
		y_j64, _ := strconv.ParseInt(string(m_ji), 10, 64)
		yji_k[i] = big.NewInt(y_j64)
	}
	proof7, points2 := zkSigma.GenLElGDecDL(secp256k1, G1, PriKey.P, yj_k[0], yj_k[1], secp256k1.ScalarBaseMult(yji_k[0]), PriKey.X, yji_k[0], []byte("proof7"))
	valid0 := zkSigma.VeriLElGEnc(secp256k1, points0, PriKey.P, yj_k[0], yj_k[1], proof0, []byte("zkproof0"))
	fmt.Printf("LElGamal.Enc() proof validation: %v\n", valid0)
	veriP := kzg.VerifyBatchProof(srs, com_k, proof_k, xij_k, yji_k)
	ki, _ := kzg.LagrangeInterpolation(xij_k, yji_k)
	fmt.Printf("ki Verification Passed? %v\n", veriP)
	fmt.Printf("The interpolation of distributed value k: %d\n", ki[0])
	//=== 3-Offline-Presignature(Round 2b-Online_BMtP) ===
	valid7 := zkSigma.VeriLElGDecDL(secp256k1, points2, yji_k[1], proof7, []byte("proof7"))
	fmt.Printf("LElGamal.Dec() proof validation: %v\n", valid7)
	e1, d1 := BMtP.OnBMtP1(Zq, ki[0], beta_i, triple1)
	e2, d2 := BMtP.OnBMtP1(Zq, ki[0], xi, triple2)
	ei_1 := make([]*big.Int, n)
	ei_1[0] = e1
	for i := 1; i <= n; i++ {
		ei_1[i-1] = big.NewInt(int64(i))
	}
	ei_2 := make([]*big.Int, n)
	ei_2[0] = e2
	for i := 1; i <= n; i++ {
		ei_2[i-1] = big.NewInt(int64(i))
	}
	di_1 := make([]*big.Int, n)
	di_1[0] = d1
	for i := 1; i <= n; i++ {
		di_1[i-1] = big.NewInt(int64(i))
	}
	di_2 := make([]*big.Int, n)
	di_2[0] = d2
	for i := 1; i <= n; i++ {
		di_2[i-1] = big.NewInt(int64(i))
	}
	//=== zk-sigma for the consistency of k_i,beta_i,x_i
	H1 := secp256k1.ScalarMult(G1, new(big.Int).Add(triple1.A, e1))
	H2 := secp256k1.ScalarMult(G2, new(big.Int).Add(triple2.B, e2))
	H3 := secp256k1.ScalarMult(G2, new(big.Int).Add(triple2.A, d1))
	H4 := secp256k1.ScalarMult(G2, new(big.Int).Add(triple2.B, d2))
	proof2 := zkSigma.GenDDLProof(secp256k1, G1, G2, H1, H2, ki[0], []byte("proof2"))
	proof3 := zkSigma.GenDDLProof(secp256k1, G1, G2, beta_G, H3, beta_i, []byte("proof3"))
	proof4 := zkSigma.GenDDLProof(secp256k1, G1, G2, secp256k1.ScalarMult(G1, xi), H4, beta_i, []byte("proof4"))
	//=== robustness for e & d
	kBeta_i := BMtP.OnBMtP2(Zq, p_i, ei_1, di_1, triple1)
	kx_i := BMtP.OnBMtP2(Zq, p_i, ei_2, di_2, triple2)
	fmt.Printf("Multiplication to Addition k*beta:%d\n", kBeta_i)
	fmt.Printf("Multiplication to Addition k*x:%d\n", kx_i)
	//=== Pre-signing Output (r,Ri,Si) and proofs ===
	InverKbeta := new(big.Int).ModInverse(kBeta_i, secp256k1.Order())
	R := secp256k1.ScalarMult(beta_G, InverKbeta)
	r_x := R.(curve.SPoint).X
	fmt.Printf("r_x:%d\n", r_x.Mod(r_x, secp256k1.Order()))
	r1, _ := rand.Int(rand.Reader, secp256k1.Order())
	C := secp256k1.Add(
		secp256k1.ScalarMult(G1, kx_i),
		secp256k1.ScalarMult(H1, r1),
	)
	R_i := secp256k1.ScalarMult(R, k_i)
	S_i := secp256k1.ScalarMult(R, kx_i)
	proof5 := zkSigma.GenDDLProof(secp256k1, G1, G2, H1, R_i, ki[0], []byte("proof5"))
	proof6, points6 := zkSigma.GenPederDlProof(secp256k1, G1, G2, H1, C, S_i, kx_i, r1, []byte("proof6"))
	return r_x.Mod(r_x, secp256k1.Order()), ki[0], kx_i, e2, d2, proof1, beta_G, proof2, H1, H2, proof3, H3, proof4, H4, proof5, R_i, C, proof6, S_i, points6
}
func OnSign(secp256k1 curve.Group, Zq gf.GF, G1 curve.Point, msg, r, ki, kx_i, e2, d2, xi, t, n *big.Int) *big.Int {
	P_i := make([]*big.Int, int(n.Int64()))
	for i := 1; i <= int(n.Int64()); i++ {
		P_i[i-1] = big.NewInt(int64(i))
	}
	//=== Compute s_i===
	term1 := new(big.Int).Mul(msg, ki)
	term2 := new(big.Int).Mul(r, kx_i)
	si := new(big.Int).Add(term1, term2)
	si.Mod(si, Zq.P)
	if n.Cmp(t) == 1 {
		//=== Compute and verify si===
		si_j := []*big.Int{si, big.NewInt(2), big.NewInt(3)}
		kzg.LagrangeInterpolation(P_i, si_j)
		term3 := new(big.Int).Mul(e2, d2)
		term4 := new(big.Int).Mul(r, term3)
		s := new(big.Int).Add(term3, term4)
		Q := secp256k1.ScalarMult(G1, xi)
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
		return s.Mod(s, Zq.P)
	}
	return big.NewInt(int64(0))
}
