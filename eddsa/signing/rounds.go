// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/poseidon"
	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	TaskName = "eddsa-signing"
)

type (
	base struct {
		*tss.Parameters
		key     *keygen.LocalPartySaveData
		data    *common.SignatureData
		temp    *localTempData
		out     chan<- tss.Message
		end     chan<- *common.SignatureData
		ok      []bool // `ok` tracks parties which have been verified by Update()
		started bool
		number  int
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
	round3 struct {
		*round2
	}
	finalization struct {
		*round3
	}
)

var (
	_ tss.Round = (*round1)(nil)
	_ tss.Round = (*round2)(nil)
	_ tss.Round = (*round3)(nil)
	_ tss.Round = (*finalization)(nil)
)

// ----- //

func (round *base) Params() *tss.Parameters {
	return round.Parameters
}

func (round *base) RoundNumber() int {
	return round.number
}

// CanProceed is inherited by other rounds
func (round *base) CanProceed() bool {
	if !round.started {
		return false
	}
	for _, ok := range round.ok {
		if !ok {
			return false
		}
	}
	return true
}

// WaitingFor is called by a Party for reporting back to the caller
func (round *base) WaitingFor() []*tss.PartyID {
	Ps := round.Parties().IDs()
	ids := make([]*tss.PartyID, 0, len(round.ok))
	for j, ok := range round.ok {
		if ok {
			continue
		}
		ids = append(ids, Ps[j])
	}
	return ids
}

func (round *base) WrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskName, round.number, round.PartyID(), culprits...)
}

// ----- //

// `ok` tracks parties which have been verified by Update()
func (round *base) resetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}

var fieldModulus = new(big.Int).SetBytes([]byte{
	0x24, 0x03, 0x4b, 0x62, 0xb0, 0x00, 0x00, 0x00,
	0x18, 0x00, 0x00, 0x00, 0xa8, 0x00, 0x00, 0x00,
	0x01, 0xd8, 0x00, 0x00, 0x00, 0x4f, 0x00, 0x00,
	0x00, 0x3b, 0x00, 0x00, 0x00, 0x01,
})

// get ssid from local params using Poseidon hash
func (round *base) getSSID() ([]byte, error) {
	ssidList := []*big.Int{
		round.EC().Params().P,
		round.EC().Params().N,
		round.EC().Params().Gx,
		round.EC().Params().Gy, // EC curve
	}
	ssidList = append(ssidList, round.Parties().IDs().Keys()...) // Parties
	BigXjList, err := crypto.FlattenECPoints(round.key.BigXj)
	if err != nil {
		return nil, round.WrapError(errors.New("read BigXj failed"), round.PartyID())
	}
	ssidList = append(ssidList, BigXjList...)                    // BigXj
	ssidList = append(ssidList, big.NewInt(int64(round.number))) // Round number
	ssidList = append(ssidList, round.temp.ssidNonce)

	// Validate and reduce inputs modulo the hardcoded field modulus
	validatedInputs := []*big.Int{}
	for _, item := range ssidList {
		reduced := new(big.Int).Mod(item, fieldModulus)
		if reduced.Sign() < 0 {
			reduced.Add(reduced, fieldModulus)
		}
		validatedInputs = append(validatedInputs, reduced)
	}

	// Compute Poseidon hash
	ssidHash, err := poseidon.Hash(validatedInputs)
	if err != nil {
		return nil, round.WrapError(errors.New("Poseidon hashing failed"), round.PartyID())
	}

	return ssidHash.Bytes(), nil
}
