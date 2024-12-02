// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package rsa

import (
	"math/big"
	"testing"
)

func TestCalculateDelta(t *testing.T) {
	ONE := big.NewInt(1)
	if CalculateDelta(0).Cmp(ONE) != 0 {
		t.Fatal("calculateDelta failed on 0")
	}

	if CalculateDelta(1).Cmp(ONE) != 0 {
		t.Fatal("calculateDelta failed on 1")
	}

	if CalculateDelta(5).Cmp(big.NewInt(120)) != 0 {
		t.Fatal("calculateDelta failed on 5")
	}
}
