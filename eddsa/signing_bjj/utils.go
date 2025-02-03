// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing_bjj

import (
	"math/big"
)

func encodedBytesToBigInt(s *[32]byte) *big.Int {
	// Use a copy so we don't screw up our original
	// memory.
	sCopy := new([32]byte)
	for i := 0; i < 32; i++ {
		sCopy[i] = s[i]
	}
	reverse(sCopy)

	bi := new(big.Int).SetBytes(sCopy[:])

	return bi
}

func copyBytes(aB []byte) *[32]byte {
	if aB == nil {
		return nil
	}
	s := new([32]byte)

	// If we have a short byte string, expand
	// it so that it's long enough.
	aBLen := len(aB)
	if aBLen < 32 {
		diff := 32 - aBLen
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)
		}
	}

	for i := 0; i < 32; i++ {
		s[i] = aB[i]
	}

	return s
}

func reverse(s *[32]byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// SwapEndianness swaps the endianness of the value encoded in xs.  If xs is
// Big-Endian, the result will be Little-Endian and viceversa.
func SwapEndianness(xs []byte) []byte {
	ys := make([]byte, len(xs))
	for i, b := range xs {
		ys[len(xs)-1-i] = b
	}
	return ys
}

// BigIntLEBytes encodes a big.Int into an array in Little-Endian.
func BigIntLEBytes(v *big.Int) [32]byte {
	le := SwapEndianness(v.Bytes())
	res := [32]byte{}
	copy(res[:], le)
	return res
}

// BigIntBEBytes encodes a big.Int into an array in Big-Endian.
func BigIntBEBytes(v *big.Int) [32]byte {
	be := v.Bytes()
	res := [32]byte{}
	copy(res[:], be)
	return res
}

// SetBigIntFromLEBytes sets the value of a big.Int from a Little-Endian
// encoded value.
func SetBigIntFromLEBytes(v *big.Int, leBuf []byte) *big.Int {
	beBuf := SwapEndianness(leBuf)
	return v.SetBytes(beBuf)
}
