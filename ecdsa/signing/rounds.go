// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/poseidon"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	TaskName = "signing"
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
	round4 struct {
		*round3
	}
	round5 struct {
		*round4
	}
	round6 struct {
		*round5
	}
	round7 struct {
		*round6
	}
	round8 struct {
		*round7
	}
	round9 struct {
		*round8
	}
	finalization struct {
		*round9
	}
)

var (
	_ tss.Round = (*round1)(nil)
	_ tss.Round = (*round2)(nil)
	_ tss.Round = (*round3)(nil)
	_ tss.Round = (*round4)(nil)
	_ tss.Round = (*round5)(nil)
	_ tss.Round = (*round6)(nil)
	_ tss.Round = (*round7)(nil)
	_ tss.Round = (*round8)(nil)
	_ tss.Round = (*round9)(nil)
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

// Define the field modulus explicitly (example for BN254; replace with actual value if different)
var fieldModulus = new(big.Int).SetBytes([]byte{
	0x24, 0x03, 0x4b, 0x62, 0xb0, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
	0xa8, 0x00, 0x00, 0x00, 0x01, 0xd8, 0x00, 0x00, 0x00, 0x4f, 0x00, 0x00,
	0x00, 0x3b, 0x00, 0x00, 0x00, 0x01,
})

func (round *base) getSSID() ([]byte, error) {
	ssidList := []*big.Int{
		round.EC().Params().P, round.EC().Params().N, round.EC().Params().B,
		round.EC().Params().Gx, round.EC().Params().Gy, // EC curve
	}
	ssidList = append(ssidList, round.Parties().IDs().Keys()...) // Parties
	BigXjList, err := crypto.FlattenECPoints(round.key.BigXj)
	if err != nil {
		return nil, round.WrapError(errors.New("read BigXj failed"), round.PartyID())
	}
	ssidList = append(ssidList, BigXjList...) // BigXj
	ssidList = append(ssidList, round.key.NTildej...)
	ssidList = append(ssidList, round.key.H1j...)
	ssidList = append(ssidList, round.key.H2j...)
	ssidList = append(ssidList, big.NewInt(int64(round.number)))
	ssidList = append(ssidList, round.temp.ssidNonce)

	validatedInputs := []*big.Int{}
	for _, item := range ssidList {

		reduced := new(big.Int).Mod(item, fieldModulus)
		if reduced.Sign() < 0 {
			reduced.Add(reduced, fieldModulus)
		}
		validatedInputs = append(validatedInputs, reduced)
	}

	const maxInputs = 16
	chunkedHashes := []*big.Int{}
	for i := 0; i < len(validatedInputs); i += maxInputs {
		end := i + maxInputs
		if end > len(validatedInputs) {
			end = len(validatedInputs)
		}
		chunk := validatedInputs[i:end]
		chunkHash, err := poseidon.Hash(chunk)
		if err != nil {
			return nil, round.WrapError(fmt.Errorf("Poseidon hashing for chunk failed: %w", err), round.PartyID())
		}
		chunkedHashes = append(chunkedHashes, chunkHash)
	}

	finalHash, err := poseidon.Hash(chunkedHashes)
	if err != nil {
		return nil, round.WrapError(fmt.Errorf("Poseidon final hashing failed: %w", err), round.PartyID())
	}

	return finalHash.Bytes(), nil
}
