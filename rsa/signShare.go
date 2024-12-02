// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package rsa

import (
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	padder "github.com/bnb-chain/tss-lib/v2/rsa/internal"
)

// SignShare represents a portion of a signature. It is generated when a message is signed by a KeyShare. t SignShare's are then combined by calling CombineSignShares, where t is the Threshold.
type SignShare struct {
	Xi *big.Int

	Index uint

	Players   uint
	Threshold uint
}

func (s SignShare) String() string {
	return fmt.Sprintf("(t,n): (%v,%v) index: %v xi: 0x%v",
		s.Threshold, s.Players, s.Index, s.Xi.Text(16))
}

// MarshalBinary encodes SignShare into a byte array in a format readable by UnmarshalBinary.
// Note: Only Index's up to math.MaxUint16 are supported
func (s *SignShare) MarshalBinary() ([]byte, error) {
	// | Players: uint16 | Threshold: uint16 | Index: uint16 | xiLen: uint16 | xi: []byte |

	if s.Players > math.MaxUint16 {
		return nil, fmt.Errorf("rsa_threshold: signshare marshall: Players is too big to fit in a uint16")
	}

	if s.Threshold > math.MaxUint16 {
		return nil, fmt.Errorf("rsa_threshold: signshare marshall: Threshold is too big to fit in a uint16")
	}

	if s.Index > math.MaxUint16 {
		return nil, fmt.Errorf("rsa_threshold: signshare marshall: Index is too big to fit in a uint16")
	}

	players := uint16(s.Players)
	threshold := uint16(s.Threshold)
	index := uint16(s.Index)

	xiBytes := s.Xi.Bytes()
	xiLen := len(xiBytes)

	if xiLen > math.MaxInt16 {
		return nil, fmt.Errorf("rsa_threshold: signshare marshall: xiBytes is too big to fit it's length in a uint16")
	}

	if xiLen == 0 {
		xiLen = 1
		xiBytes = []byte{0}
	}

	blen := 2 + 2 + 2 + 2 + xiLen
	out := make([]byte, blen)

	binary.BigEndian.PutUint16(out[0:2], players)
	binary.BigEndian.PutUint16(out[2:4], threshold)
	binary.BigEndian.PutUint16(out[4:6], index)

	binary.BigEndian.PutUint16(out[6:8], uint16(xiLen))

	copy(out[8:8+xiLen], xiBytes)

	return out, nil
}

// UnmarshalBinary converts a byte array outputted from Marshall into a SignShare or returns an error if the value is invalid
func (s *SignShare) UnmarshalBinary(data []byte) error {
	// | Players: uint16 | Threshold: uint16 | Index: uint16 | xiLen: uint16 | xi: []byte |
	if len(data) < 8 {
		return fmt.Errorf("rsa_threshold: signshare unmarshalKeyShareTest failed: data length was too short for reading Players, Threshold, Index, and xiLen")
	}

	players := binary.BigEndian.Uint16(data[0:2])
	threshold := binary.BigEndian.Uint16(data[2:4])
	index := binary.BigEndian.Uint16(data[4:6])
	xiLen := binary.BigEndian.Uint16(data[6:8])

	if xiLen == 0 {
		return fmt.Errorf("rsa_threshold: signshare unmarshalKeyShareTest failed: xi is a required field but xiLen was 0")
	}

	if uint16(len(data[8:])) < xiLen {
		return fmt.Errorf("rsa_threshold: signshare unmarshalKeyShareTest failed: data length was too short for reading xi, needed: %d found: %d", xiLen, len(data[6:]))
	}

	xi := big.Int{}
	bytes := make([]byte, xiLen)
	copy(bytes, data[8:8+xiLen])
	xi.SetBytes(bytes)

	s.Players = uint(players)
	s.Threshold = uint(threshold)
	s.Index = uint(index)
	s.Xi = &xi

	return nil
}

// PadHash MUST be called before signing a message
func PadHash(padder padder.Padder, hash crypto.Hash, pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	// Sign(Pad(Hash(M)))

	hasher := hash.New()
	hasher.Write(msg)
	digest := hasher.Sum(nil)

	return padder.Pad(pub, hash, digest)
}

type Signature = []byte

// CombineSignShares combines t SignShare's to produce a valid signature
func CombineSignShares(pub *rsa.PublicKey, shares []SignShare, msg []byte) (Signature, error) {
	players := shares[0].Players
	threshold := shares[0].Threshold

	for i := range shares {
		if shares[i].Players != players {
			return nil, errors.New("rsa_threshold: shares didn't have consistent players")
		}
		if shares[i].Threshold != threshold {
			return nil, errors.New("rsa_threshold: shares didn't have consistent threshold")
		}
	}

	if uint(len(shares)) < threshold {
		return nil, errors.New("rsa_threshold: insufficient shares for the threshold")
	}

	w := big.NewInt(1)
	delta := CalculateDelta(int64(players))
	// i_1 ... i_k
	for _, share := range shares {
		// λ(S, 0, i)
		lambda, err := ComputeLambda(delta, shares, 0, int64(share.Index))
		if err != nil {
			return nil, err
		}
		// 2λ
		var exp big.Int
		exp.Add(lambda, lambda) // faster than TWO * lambda

		// we need to handle negative λ's (aka inverse), so abs it, compare, and if necessary modinverse
		abslam := big.Int{}
		abslam.Abs(&exp)
		var tmp big.Int
		// x_i^{|2λ|}
		tmp.Exp(share.Xi, &abslam, pub.N)
		if abslam.Cmp(&exp) == 1 {
			tmp.ModInverse(&tmp, pub.N)
		}
		// TODO  first compute all the powers for the negative exponents (but don't invert yet); multiply these together and then invert all at once. This is ok since (ab)^-1 = a^-1 b^-1

		w.Mul(w, &tmp).Mod(w, pub.N)
	}
	w.Mod(w, pub.N)

	// e′ = 4∆^2
	eprime := big.Int{}
	eprime.Mul(delta, delta)     // faster than delta^TWO
	eprime.Add(&eprime, &eprime) // faster than FOUR * eprime
	eprime.Add(&eprime, &eprime)

	// e′a + eb = 1
	a := big.Int{}
	b := big.Int{}
	e := big.NewInt(int64(pub.E))
	tmp := big.Int{}
	tmp.GCD(&a, &b, &eprime, e)

	// TODO You can compute a earlier and multiply a into the exponents used when computing w.
	// w^a
	wa := big.Int{}
	wa.Exp(w, &a, pub.N) // TODO justification
	// x^b
	x := big.Int{}
	x.SetBytes(msg)
	xb := big.Int{}
	xb.Exp(&x, &b, pub.N) // TODO justification
	// y = w^a * x^b
	y := big.Int{}
	y.Mul(&wa, &xb).Mod(&y, pub.N)

	// verify that signature is valid by checking x == y^e.
	ye := big.Int{}
	ye.Exp(&y, e, pub.N)
	if ye.Cmp(&x) != 0 {
		return nil, errors.New("rsa: internal error")
	}

	// ensure signature has the right size.
	sig := y.FillBytes(make([]byte, pub.Size()))

	return sig, nil
}

// computes lagrange Interpolation for the shares
// i must be an id 0..l but not in S
// j must be in S
func ComputeLambda(delta *big.Int, S []SignShare, i, j int64) (*big.Int, error) {
	if i == j {
		return nil, errors.New("rsa_threshold: i and j can't be equal by precondition")
	}
	// these are just to check preconditions
	foundi := false
	foundj := false

	// λ(s, i, j) = ∆( (  π{j'∈S\{j}} (i - j')  ) /  (  π{j'∈S\{j}} (j - j') ) )

	num := int64(1)
	den := int64(1)

	// ∈ S
	for _, s := range S {
		// j'
		jprime := int64(s.Index)
		// S\{j}
		if jprime == j {
			foundj = true
			continue
		}
		if jprime == i {
			foundi = false
			break
		}
		//  (i - j')
		num *= i - jprime
		// (j - j')
		den *= j - jprime
	}

	// ∆ * (num/den)
	var lambda big.Int
	// (num/den)
	lambda.Div(big.NewInt(num), big.NewInt(den))
	// ∆ * (num/den)
	lambda.Mul(delta, &lambda)

	if foundi {
		return nil, fmt.Errorf("rsa_threshold: i: %d should not be in S", i)
	}

	if !foundj {
		return nil, fmt.Errorf("rsa_threshold: j: %d should be in S", j)
	}

	return &lambda, nil
}
