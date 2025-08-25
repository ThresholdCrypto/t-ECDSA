package Sign

import (
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
	srs *kzg.TrustedSetup, PriKey *NeELGa.PrivateKey, xi *big.Int, triple1, triple2 BMtP.BeaverTriple, t int) (*big.Int,
	*big.Int, *big.Int, *big.Int, *big.Int, *zkSigma.SchnorrProof, curve.Point, *zkSigma.DoubleDLProof, curve.Point, curve.Point) {

	//=== 1-Offline-Presignature(Round 1-beta*G) ===
	pi := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	k_i := big.NewInt(int64(3))
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
	com_k, proof_k, xij_k, yj_k := kGen.PVSS(srs, t, k_i, PriKey)
	yji_k := make([]*big.Int, len(yj_k)/2)
	for i := 0; i < len(yji_k); i++ {
		m_ji, _ := PriKey.Decrypt(yj_k[i*2], yj_k[i*2+1])
		y_j64, _ := strconv.ParseInt(string(m_ji), 10, 64)
		yji_k[i] = big.NewInt(y_j64)
	}
	veriP := kzg.VerifyBatchProof(srs, com_k, proof_k, xij_k, yji_k)
	ki, _ := kzg.LagrangeInterpolation(xij_k, yji_k)
	fmt.Printf("Verification Passed? %v\n", veriP)
	fmt.Printf("Interpolation distributed value k: %d\n", ki[0])
	//=== 3-Offline-Presignature(Round 2b-Online_BMtP) ===
	e1, d1 := BMtP.OnBMtP1(Zq, ki[0], beta_i, triple1)
	e2, d2 := BMtP.OnBMtP1(Zq, ki[0], xi, triple2)
	ei_1 := []*big.Int{e1, big.NewInt(2), big.NewInt(3)}
	di_1 := []*big.Int{d1, big.NewInt(2), big.NewInt(3)}
	ei_2 := []*big.Int{e2, big.NewInt(2), big.NewInt(3)}
	di_2 := []*big.Int{d2, big.NewInt(2), big.NewInt(3)}
	//=== zk-sigma for the consistency of k_i,beta_i,x_i
	H1 := secp256k1.ScalarMult(G1, k_i)
	H2 := secp256k1.ScalarMult(G2, k_i)
	proof2 := zkSigma.GenDDLProof(secp256k1, G1, G2, H1, H2, k_i, []byte("proof2"))
	//=== robustness for e & d
	kBeta_i := BMtP.OnBMtP2(Zq, pi, ei_1, di_1, triple1)
	kx_i := BMtP.OnBMtP2(Zq, pi, ei_2, di_2, triple2)
	fmt.Printf("Multiplication to Addition k*beta:%d\n", kBeta_i)
	fmt.Printf("Multiplication to Addition k*x:%d\n", kx_i)
	//=== Output(r,Ri,Si) ===
	InverKbeta := new(big.Int).ModInverse(kBeta_i, secp256k1.Order())
	R := secp256k1.ScalarMult(beta_G, InverKbeta)
	r_x := R.(curve.SPoint).X
	fmt.Printf("r_x:%d\n", r_x.Mod(r_x, secp256k1.Order()))
	return r_x.Mod(r_x, secp256k1.Order()), ki[0], kx_i, e2, d2, proof1, beta_G, proof2, H1, H2
}
func On_Sign(Zq gf.GF, G curve.Point, msg, r, ki, kx_i, e2, d2 *big.Int) *big.Int {
	P_i := make([]*big.Int, 3)
	for i := 1; i <= 3; i++ {
		P_i[i-1] = big.NewInt(int64(i))
	}
	//=== Compute s_i===
	term1 := new(big.Int).Mul(msg, ki)
	term2 := new(big.Int).Mul(r, kx_i)
	si := new(big.Int).Add(term1, term2)
	si.Mod(si, Zq.P)
	//=== Compute s===
	si_j := []*big.Int{si, big.NewInt(2), big.NewInt(3)}
	kzg.LagrangeInterpolation(P_i, si_j)
	term3 := new(big.Int).Mul(e2, d2)
	term4 := new(big.Int).Mul(r, term3)
	s := new(big.Int).Add(term3, term4)
	return s.Mod(s, Zq.P)
}
