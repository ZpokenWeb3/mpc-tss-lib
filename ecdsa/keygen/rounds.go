// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	TaskName = "ecdsa-keygen"
)

type (
	base struct {
		*tss.Parameters
		save    *LocalPartySaveData
		temp    *localTempData
		out     chan<- tss.Message
		end     chan<- *LocalPartySaveData
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
)

var (
	_ tss.Round = (*round1)(nil)
	_ tss.Round = (*round2)(nil)
	_ tss.Round = (*round3)(nil)
	_ tss.Round = (*round4)(nil)
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

// get ssid from local params
// changed to only SHA as poseidon should be only in signing
/*
 func (round *base) getSSID(usePoseidon bool) ([]byte, error) {
	ssidList := []*big.Int{
		round.EC().Params().P,
		round.EC().Params().N,
		round.EC().Params().Gx,
		round.EC().Params().Gy,
	}
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)
	ssidList = append(ssidList, big.NewInt(int64(round.number)))
	ssidList = append(ssidList, round.temp.ssidNonce)

	if usePoseidon {
		poseidonPrime, success := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
		if !success {
			return nil, fmt.Errorf("failed to parse Poseidon prime")
		}
		for i, input := range ssidList {
			ssidList[i] = new(big.Int).Mod(input, poseidonPrime)
		}

		ssidHash, err := poseidon.Hash(ssidList)
		if err != nil {
			return nil, fmt.Errorf("failed to compute Poseidon hash for SSID: %w", err)
		}
		return ssidHash.Bytes(), nil
	}
	ssid := common.SHA512_256i(ssidList...).Bytes()
	return ssid, nil
}
*/

// get ssid from local params
func (round *base) getSSID() ([]byte, error) {
	ssidList := []*big.Int{round.EC().Params().P, round.EC().Params().N, round.EC().Params().Gx, round.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)
	ssidList = append(ssidList, big.NewInt(int64(round.number))) // round number
	ssidList = append(ssidList, round.temp.ssidNonce)
	ssid := common.SHA512_256i(ssidList...).Bytes()

	return ssid, nil
}
