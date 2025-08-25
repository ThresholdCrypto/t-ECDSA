package curve

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// secpP implements the Point interface
type SPoint struct {
	X, Y *big.Int
}

// sGroup implements the Group interface
type sGroup struct {
	curve *secp256k1.BitCurve
	pow   *big.Int
}

// NewSecp256k1Group returns the impelementation of the group interface with the secp256k1 elliptic curve
func NewSecp256k1Group() Group {
	cur := secp256k1.S256()
	return &sGroup{cur, new(big.Int).Sub(cur.N, big.NewInt(1))}
}

func (g sGroup) Order() *big.Int {
	return g.curve.N
}

func (g sGroup) Gen() Point {
	return SPoint{g.curve.Gx, g.curve.Gy}
}

func (g sGroup) Add(a Point, b Point) Point {
	var resultX, resultY *big.Int
	as := a.(SPoint)
	bs := b.(SPoint)

	if as.X == nil && as.Y == nil {
		if bs.X == nil && bs.Y == nil {
			resultX = nil
			resultY = nil
		} else {
			resultX = new(big.Int).Set(bs.X)
			resultY = new(big.Int).Set(bs.Y)
		}
	} else if bs.X == nil && bs.Y == nil {
		resultX = new(big.Int).Set(as.X)
		resultY = new(big.Int).Set(as.Y)
	} else if (as.X.Cmp(bs.X) == 0) && (as.Y.Cmp(bs.Y) == 0) {
		resultX, resultY = g.curve.Double(as.X, as.Y)
	} else {
		resultX, resultY = g.curve.Add(as.X, as.Y, bs.X, bs.Y)
	}

	return SPoint{resultX, resultY}
}

func (g sGroup) Neutral() Point {
	return SPoint{nil, nil}
}

func (g sGroup) Neg(a Point) Point {
	return g.ScalarMult(a, g.pow)
}

// scale has to be a nonnegative integer
func (g sGroup) ScalarMult(a Point, scale *big.Int) Point {
	if len(scale.Bytes()) > 32 {
		scale.Mod(scale, g.Order())
	}
	resultX, resultY := g.curve.ScalarMult(a.(SPoint).X, a.(SPoint).Y, scale.Bytes())
	return SPoint{resultX, resultY}
}

// scale has to be a nonnegative integer
func (g sGroup) ScalarBaseMult(scale *big.Int) Point {
	if len(scale.Bytes()) > 32 {
		scale.Mod(scale, g.Order())
	}
	resultX, resultY := g.curve.ScalarBaseMult(scale.Bytes())
	return SPoint{resultX, resultY}
}

func (g sGroup) Equal(a Point, b Point) bool {
	as := a.(SPoint)
	bs := b.(SPoint)
	if as.X == nil && as.Y == nil && bs.X == nil && bs.Y == nil {
		return true
	} else if (as.X == nil && as.Y == nil) || (bs.X == nil && bs.Y == nil) {
		return false
	}
	return (as.X.Cmp(bs.X) == 0) && (as.Y.Cmp(bs.Y) == 0)
}

func (g sGroup) Encode(a Point, w io.Writer) error {
	buf := make([]byte, 4)
	as := a.(SPoint)
	// encoding of a neutral element is [0 0 0 0]
	if as.X == nil {
		binary.BigEndian.PutUint32(buf, uint32(0))
		if _, err := w.Write(buf); err != nil {
			return err
		}
		return nil
	}
	lenX := uint32(len(as.X.Bytes()))
	lenY := uint32(len(as.Y.Bytes()))
	buf = make([]byte, 8, 8+lenX+lenY)
	binary.BigEndian.PutUint32(buf[:4], lenX)
	binary.BigEndian.PutUint32(buf[4:8], lenY)
	buf = append(buf, as.X.Bytes()...)
	buf = append(buf, as.Y.Bytes()...)

	if _, err := w.Write(buf); err != nil {
		return err
	}

	return nil
}

func (g sGroup) Decode(r io.Reader) (Point, error) {
	lenBytes := make([]byte, 8)
	n, err := r.Read(lenBytes)
	if err != nil {
		return nil, err
	}
	if n < 8 {
		return nil, fmt.Errorf("Too few bytes for lenX and lenY: expected 8, got %d", n)
	}

	lenX := binary.BigEndian.Uint32(lenBytes[:4])
	if lenX == 0 {
		return SPoint{nil, nil}, nil
	}

	lenY := binary.BigEndian.Uint32(lenBytes[4:8])
	xyBytes := make([]byte, lenX+lenY)
	n, err = r.Read(xyBytes)
	if err != nil {
		return nil, err
	}
	if uint32(n) < lenX+lenY {
		return nil, fmt.Errorf("Too few bytes for lenX and lenY: expected %d, got %d", lenX+lenY, n)
	}
	x := new(big.Int).SetBytes(xyBytes[:lenX])
	y := new(big.Int).SetBytes(xyBytes[lenX:])

	return SPoint{x, y}, nil
}
