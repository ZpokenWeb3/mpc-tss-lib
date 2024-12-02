// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package rsa

import (
	"math/big"
)

func CalculateDelta(l int64) *big.Int {
	// ∆ = l!
	delta := big.Int{}
	delta.MulRange(1, l)
	return &delta
}
