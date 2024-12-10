// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package vss_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v2/common"
	. "github.com/bnb-chain/tss-lib/v2/crypto/vss"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

func TestCheckIndexesDup(t *testing.T) {
	indexes := make([]*big.Int, 0)
	for i := 0; i < 1000; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}
	_, e := CheckIndexes(tss.EC(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, indexes[99])
	_, e = CheckIndexes(tss.EC(), indexes)
	assert.Error(t, e)
}

func TestCheckIndexesZero(t *testing.T) {
	indexes := make([]*big.Int, 0)
	for i := 0; i < 1000; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}
	_, e := CheckIndexes(tss.EC(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, tss.EC().Params().N)
	_, e = CheckIndexes(tss.EC(), indexes)
	assert.Error(t, e)
}

func TestCreate(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}

	vs, _, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.Nil(t, err)

	assert.Equal(t, threshold+1, len(vs))
	// assert.Equal(t, num, params.NumShares)

	assert.Equal(t, threshold+1, len(vs))

	// ensure that each vs has two points on the curve
	for i, pg := range vs {
		assert.NotZero(t, pg.X())
		assert.NotZero(t, pg.Y())
		assert.True(t, pg.IsOnCurve())
		assert.NotZero(t, vs[i].X())
		assert.NotZero(t, vs[i].Y())
	}
}

func TestCreateBJJ(t *testing.T) {
	num, threshold := 5, 3

	ec := tss.BabyJubJub()
	secret := common.GetRandomPositiveInt(rand.Reader, ec.Params().N)

	fmt.Printf("\n ROUND 3  round.Params().N() %v \n", ec.Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, ec.Params().N))
	}

	vs, _, err := Create(ec, threshold, secret, ids, rand.Reader)
	assert.Nil(t, err)

	assert.Equal(t, threshold+1, len(vs))
	// assert.Equal(t, num, params.NumShares)

	assert.Equal(t, threshold+1, len(vs))

	// ensure that each vs has two points on the curve
	for i, pg := range vs {
		assert.NotZero(t, pg.X())
		assert.NotZero(t, pg.Y())
		assert.True(t, pg.IsOnCurve())
		assert.NotZero(t, vs[i].X())
		assert.NotZero(t, vs[i].Y())
	}
}

func TestVerify(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}

	vs, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	for i := 0; i < num; i++ {
		assert.True(t, shares[i].Verify(tss.EC(), threshold, vs))
	}
}

func TestVerifyBJJ(t *testing.T) {
	num, threshold := 5, 3

	ec := tss.BabyJubJub()
	secret := common.GetRandomPositiveInt(rand.Reader, ec.Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, ec.Params().N))
	}

	vs, shares, err := Create(ec, threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	for i := 0; i < num; i++ {
		assert.True(t, shares[i].Verify(ec, threshold, vs))
	}
}

func TestReconstruct(t *testing.T) {
	num, threshold := 5, 3
	secret := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}

	_, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	secret2, err2 := shares[:threshold-1].ReConstruct(tss.EC())
	assert.Error(t, err2) // not enough shares to satisfy the threshold
	assert.Nil(t, secret2)

	secret3, err3 := shares[:threshold].ReConstruct(tss.EC())
	assert.NoError(t, err3)
	assert.NotZero(t, secret3)

	secret4, err4 := shares[:num].ReConstruct(tss.EC())
	assert.NoError(t, err4)
	assert.NotZero(t, secret4)
}

func TestReconstructBJJ(t *testing.T) {
	num, threshold := 5, 3

	ec := tss.BabyJubJub()
	secret := common.GetRandomPositiveInt(rand.Reader, ec.Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, ec.Params().N))
	}

	_, shares, err := Create(ec, threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	secret2, err2 := shares[:threshold-1].ReConstruct(ec)
	assert.Error(t, err2) // not enough shares to satisfy the threshold
	assert.Nil(t, secret2)

	secret3, err3 := shares[:threshold].ReConstruct(ec)
	assert.NoError(t, err3)
	assert.NotZero(t, secret3)

	secret4, err4 := shares[:num].ReConstruct(ec)
	assert.NoError(t, err4)
	assert.NotZero(t, secret4)
}

// NewIntFromString creates a new big.Int from a decimal integer encoded as a
// string.  It will panic if the string is not a decimal integer.
func NewIntFromString(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10) //nolint:gomnd
	if !ok {
		panic(fmt.Sprintf("Bad base 10 string %s", s))
	}
	return v
}

func TestMul(t *testing.T) {
	ec := tss.BabyJubJub()
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	c := NewIntFromString("2736030358979909402780800718157159386076813972158567259200215660948447373041")
	a := g.ScalarMult(c)
	fmt.Printf("Point: (%v, %v)\n", a.X(), a.Y())
}
