// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

// RejectionSample implements the rejection sampling logic for converting a
// SHA512/256 hash to a value between 0-q
func RejectionSample(q *big.Int, eHash *big.Int) *big.Int { // e' = eHash
	e := eHash.Mod(eHash, q)
	return e
}

func RejectionSampleWithPoseidon(q *big.Int, inputs []*big.Int) (*big.Int, error) {
	// Compute the Poseidon hash
	eHash, err := poseidon.Hash(inputs)
	if err != nil {
		return nil, err
	}
	e := eHash.Mod(eHash, q)
	return e, nil
}
