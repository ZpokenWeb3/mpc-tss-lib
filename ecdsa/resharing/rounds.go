// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

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
	TaskName = "ecdsa-resharing"
)

type (
	base struct {
		*tss.ReSharingParameters
		temp        *localTempData
		input, save *keygen.LocalPartySaveData
		out         chan<- tss.Message
		end         chan<- *keygen.LocalPartySaveData
		oldOK,      // old committee "ok" tracker
		newOK []bool // `ok` tracks parties which have been verified by Update(); this one is for the new committee
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
)

var (
	_ tss.Round = (*round1)(nil)
	_ tss.Round = (*round2)(nil)
	_ tss.Round = (*round3)(nil)
	_ tss.Round = (*round4)(nil)
	_ tss.Round = (*round5)(nil)
)

// ----- //

func (round *base) Params() *tss.Parameters {
	return round.ReSharingParameters.Parameters
}

func (round *base) ReSharingParams() *tss.ReSharingParameters {
	return round.ReSharingParameters
}

func (round *base) RoundNumber() int {
	return round.number
}

// CanProceed is inherited by other rounds
func (round *base) CanProceed() bool {
	if !round.started {
		return false
	}
	for _, ok := range append(round.oldOK, round.newOK...) {
		if !ok {
			return false
		}
	}
	return true
}

// WaitingFor is called by a Party for reporting back to the caller
func (round *base) WaitingFor() []*tss.PartyID {
	oldPs := round.OldParties().IDs()
	newPs := round.NewParties().IDs()
	idsMap := make(map[*tss.PartyID]bool)
	ids := make([]*tss.PartyID, 0, len(round.oldOK))
	for j, ok := range round.oldOK {
		if ok {
			continue
		}
		idsMap[oldPs[j]] = true
	}
	for j, ok := range round.newOK {
		if ok {
			continue
		}
		idsMap[newPs[j]] = true
	}
	// consolidate into the list
	for id := range idsMap {
		ids = append(ids, id)
	}
	return ids
}

func (round *base) WrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskName, round.number, round.PartyID(), culprits...)
}

// ----- //

// `oldOK` tracks parties which have been verified by Update()
func (round *base) resetOK() {
	for j := range round.oldOK {
		round.oldOK[j] = false
	}
	for j := range round.newOK {
		round.newOK[j] = false
	}
}

// sets all pairings in `oldOK` to true
func (round *base) allOldOK() {
	for j := range round.oldOK {
		round.oldOK[j] = true
	}
}

// sets all pairings in `newOK` to true
func (round *base) allNewOK() {
	for j := range round.newOK {
		round.newOK[j] = true
	}
}
func hashWithPoseidon(inputs []*big.Int) ([]byte, error) {
	const maxInputs = 16
	var hashes []*big.Int

	for i := 0; i < len(inputs); i += maxInputs {
		end := i + maxInputs
		if end > len(inputs) {
			end = len(inputs)
		}
		chunk := inputs[i:end]
		fmt.Printf("Hashing chunk: %v\n", chunk) // Debug log
		chunkHash, err := poseidon.Hash(chunk)
		if err != nil {
			return nil, fmt.Errorf("failed to hash chunk %d-%d: %w", i, end, err)
		}
		fmt.Printf("Chunk hash: %v\n", chunkHash) // Debug log
		hashes = append(hashes, chunkHash)
	}

	finalHash, err := poseidon.Hash(hashes)
	if err != nil {
		return nil, fmt.Errorf("failed to hash final hashes: %w", err)
	}
	fmt.Printf("Final hash: %v\n", finalHash) // Debug log
	return finalHash.Bytes(), nil
}

func (round *base) getSSID(usePoseidon bool) ([]byte, error) {
	ssidList := []*big.Int{
		round.EC().Params().P,
		round.EC().Params().N,
		round.EC().Params().B,
		round.EC().Params().Gx,
		round.EC().Params().Gy,
	}
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)
	BigXjList, err := crypto.FlattenECPoints(round.input.BigXj)
	if err != nil {
		return nil, round.WrapError(errors.New("read BigXj failed"), round.PartyID())
	}
	ssidList = append(ssidList, BigXjList...)
	ssidList = append(ssidList, round.input.NTildej...)
	ssidList = append(ssidList, round.input.H1j...)
	ssidList = append(ssidList, round.input.H2j...)
	ssidList = append(ssidList, big.NewInt(int64(round.number)))
	ssidList = append(ssidList, round.temp.ssidNonce)

	if usePoseidon {
		// Reduce inputs modulo Poseidon prime
		poseidonPrime, success := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
		if !success {
			return nil, errors.New("failed to parse Poseidon prime")
		}
		for i, input := range ssidList {
			ssidList[i] = new(big.Int).Mod(input, poseidonPrime)
		}

		// Hash with Poseidon in chunks
		ssidHash, err := hashWithPoseidon(ssidList)
		if err != nil {
			return nil, round.WrapError(errors.New("Poseidon hash computation failed"), round.PartyID())
		}
		return ssidHash, nil
	}

	// Fallback to SHA-512/256
	ssid := common.SHA512_256i(ssidList...).Bytes()
	return ssid, nil
}
