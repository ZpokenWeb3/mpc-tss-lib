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
	"github.com/bnb-chain/tss-lib/v2/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v2/crypto/poseidon"
	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// round 1 represents round 1 of the signing part of the EDDSA TSS spec
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- *common.SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1},
	}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	round.temp.ssidNonce = new(big.Int).SetUint64(0)
	var err error
	round.temp.ssid, err = round.getSSID()
	if err != nil {
		return round.WrapError(err)
	}

	// 1. select ri
	ri := common.GetRandomPositiveInt(round.Rand(), round.Params().EC().Params().N)

	// 2. make commitment
	pointRi := crypto.ScalarBaseMult(round.Params().EC(), ri)

	// Combine X and Y coordinates of pointRi into byte slices
	xBytes := pointRi.X().Bytes()
	yBytes := pointRi.Y().Bytes()

	// Use Poseidon to hash the combined coordinates
	poseidonHash, err := poseidon.HashBytes(append(xBytes, yBytes...))
	if err != nil {
		return round.WrapError(fmt.Errorf("poseidon hash computation failed: %v", err))
	}

	// Create the commitment using Poseidon hash
	cmt := commitments.HashCommitDecommit{
		C: new(big.Int).SetBytes(poseidonHash.Bytes()),                              // Convert Poseidon hash to *big.Int
		D: []*big.Int{new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)}, // X and Y as []*big.Int
	}

	// Store the deCommit value
	round.temp.deCommit = cmt.D

	// 4. broadcast commitment
	r1msg2 := NewSignRound1Message(round.PartyID(), cmt.C) // Pass cmt.C directly
	round.temp.signRound1Messages[round.PartyID().Index] = r1msg2
	round.out <- r1msg2

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi
	ks := round.key.Ks

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	wi := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks)

	round.temp.wi = wi
	return nil
}
