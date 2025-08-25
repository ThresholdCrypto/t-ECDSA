package ElGamal

import (
	"crypto/sha512"
	"fmt"
	"github.com/lavode/secret-sharing/gf"
	"github.com/lavode/secret-sharing/secretshare"
	"math/big"
	"t_ECDSA/pkg/group"
)

// hashByteSize is the size - in bytes - of the hash algorithm used by this
// implementation of hashed ElGamal.
// In our case we use SHA512, hence 64 bytes.
// All messages to encrypt must contain exactly hashByteSize bytes, and all
// ciphertexts will also be of the same length.
const hashByteSize int = 64

// PublicKey represents a public key of the ElGamal cryptosystem.
type PublicKey struct {
	group.SchnorrGroup
	// Public key y = g^x mod p
	Y *big.Int
}

// Zp returns the finite field (Z / pZ), which G - over which the ElGamal
// cryptosystem is defined - is a subgroup of.
func (pk *PublicKey) Zp() (gf.GF, error) {
	return gf.NewGF(pk.P)
}

// Zq returns the finite field (Z / qZ), which is used in the secret sharing
// scheme.
func (pk *PublicKey) Zq() (gf.GF, error) {
	return gf.NewGF(pk.Q)
}

// PrivateKey represents a private key of the ElGamal cryptosystem.
type PrivateKey struct {
	// Private exponent from (Z / qZ)
	X *big.Int
}

// PrivateKeyShare represents a private key share of the distributed ElGamal
// cryptosystem.
type PrivateKeyShare secretshare.Share

// DecryptionShare represents a single party's decryption share.
type DecryptionShare secretshare.Share

// Ciphertext represents a ciphertext of the hashed ElGamal cryptosystem.
type Ciphertext struct {
	// R = g^x mod p
	R *big.Int
	// C = H(y^r) XOR m
	C []byte
}

// KeyGen implements key generation for a distributed ElGamal cryptosystem. It
// is to be executed by a trusted dealer, who can then send out the individual
// key shares.
//
// Secret sharing is based on polynomials over a finite field.
//
// Parameters:
// - pBits: Bit length of modulus p of multiplicative group of integers modulo p
// - qBits: Bit length of prime order of subgroup G over which ElGamal operates
// - t: Number of secret shares which should be able to reconstruct private key
// - n: Number of total secret shares to generate
func KeyGen(schnorr group.SchnorrGroup, t int, n int) (PublicKey, PrivateKey, []PrivateKeyShare, error) {
	var pub PublicKey
	var priv PrivateKey
	shares := make([]PrivateKeyShare, n)

	pub.P = schnorr.P
	pub.Q = schnorr.Q
	pub.G = schnorr.G

	// (Z/qZ) is used for:
	// - Generation of a private key x, such that `g^x` is an element of G
	// - Secret sharing using polynomials over (Z/qZ)
	zq, err := pub.Zq()
	if err != nil {
		return pub, priv, shares, err
	}

	// (Z/pZ) is used for all operations *within* G, as it's a subgroup of
	// (Z/pZ)
	zp, err := pub.Zp()
	if err != nil {
		return pub, priv, shares, err
	}

	x, err := zq.Rand()
	if err != nil {
		return pub, priv, shares, err
	}
	priv.X = x

	pub.Y = zp.Exp(pub.G, x)

	tnShares, _, err := secretshare.TOutOfN(priv.X, t, n, zq)
	if err != nil {
		return pub, priv, shares, err
	}
	for i, share := range tnShares {
		shares[i] = PrivateKeyShare(share)
	}

	return pub, priv, shares, nil
}

// Enc encrypts a message using hashed ElGamal.
//
// Parameters:
// - pub: Public key to use for encryption
// - message: Message to encrypt. Must be of length hashByteSize
//
// An error is returned if encryption fails.
func Enc(pub PublicKey, message []byte) (Ciphertext, error) {
	var ctxt Ciphertext
	// Using SHA512
	ctxt.C = make([]byte, hashByteSize)

	if len(message) != hashByteSize {
		return ctxt, fmt.Errorf("Message must be %d bytes; got %d", hashByteSize, len(message))
	}

	zq, err := pub.Zq()
	if err != nil {
		return ctxt, err
	}
	zp, err := pub.Zp()
	if err != nil {
		return ctxt, err
	}

	r, err := zq.Rand()
	if err != nil {
		return ctxt, err
	}
	ctxt.R = zp.Exp(pub.G, r) // g^r = R

	yr := zp.Exp(pub.Y, r) // y^r

	key := sha512.Sum512(yr.Bytes())

	for i, keyByte := range key {
		ctxt.C[i] = message[i] ^ keyByte
	}

	return ctxt, nil
}

// Dec creates a single decryption share of a ciphertext based on the passed
// share of the private key.
//
// t of these can be passed to Recover() to decrypt the ciphertext.
func Dec(pub PublicKey, keyShare PrivateKeyShare, ctxt Ciphertext) (DecryptionShare, error) {
	decryptionShare := DecryptionShare(
		secretshare.Share{
			ID: keyShare.ID,
		},
	)

	zp, err := pub.Zp()
	if err != nil {
		return decryptionShare, err
	}

	// While the coefficients of the secret sharing polynomials are over
	// (Z/qZ), the values (by virtue of being a power of a generator of G)
	// are in (Z/pZ)
	decryptionShare.Value = zp.Exp(ctxt.R, keyShare.Value) // R^{x_i} mod p

	return decryptionShare, nil
}

// Recover decrypts a ciphertext using t decryption shares.
func Recover(pub PublicKey, decryptionShares []DecryptionShare, ctxt Ciphertext) ([]byte, error) {
	msg := make([]byte, hashByteSize)

	xs := make([]*big.Int, len(decryptionShares))
	for i, share := range decryptionShares {
		xs[i] = big.NewInt(int64(share.ID))
	}

	zp, err := pub.Zp()
	if err != nil {
		return msg, err
	}

	// Mind that secret sharing happens over (Z/qZ)
	zq, err := pub.Zq()
	if err != nil {
		return msg, err
	}

	// Starting with 1, as identity of multiplication
	z := big.NewInt(1)

	for i, share := range decryptionShares {
		// Polynomial's coefficients (and such also lagrange
		// coefficients) are over (Z/qZ)
		bp := gf.BasePolynomial(i, xs, zq)
		// But the value we reconstruct is in G, so we operate over (Z/pZ)
		factor := zp.Exp(share.Value, bp)
		z = zp.Mul(z, factor)
	}

	key := sha512.Sum512(z.Bytes())

	for i, keyByte := range key {
		msg[i] = ctxt.C[i] ^ keyByte
	}

	return msg, nil
}
