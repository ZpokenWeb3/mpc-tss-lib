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

	"github.com/agl/ed25519/edwards25519"
	"github.com/bnb-chain/tss-lib/v2/crypto/poseidon"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	sumS := round.temp.si
	for j := range round.Parties().IDs() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		sjBytes := bigIntToEncodedBytes(r3msg.UnmarshalS())
		var tmpSumS [32]byte
		edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), sjBytes)
		sumS = &tmpSumS
	}
	s := encodedBytesToBigInt(sumS)

	// save the signature for final output
	round.data.Signature = append(bigIntToEncodedBytes(round.temp.r)[:], sumS[:]...)
	round.data.R = round.temp.r.Bytes()
	round.data.S = s.Bytes()

	fmt.Printf("Message before hashing: %x\n", round.temp.m.Bytes())

	// Use Poseidon to hash the message
	// Pad the message to a fixed length before hashing
	msgBytes := round.temp.m.Bytes()
	paddedMsg := make([]byte, 32) // Poseidon often expects 32-byte inputs
	copy(paddedMsg[32-len(msgBytes):], msgBytes)

	poseidonHash, err := poseidon.HashBytes(paddedMsg)
	if err != nil {
		return round.WrapError(fmt.Errorf("poseidon hash computation failed: %v", err))
	}

	if err != nil {
		return round.WrapError(fmt.Errorf("poseidon hash computation failed: %v", err))
	}

	// Convert Poseidon hash output to the appropriate format
	round.data.M = poseidonHash.Bytes()

	pk := edwards.PublicKey{
		Curve: round.Params().EC(),
		X:     round.key.EDDSAPub.X(),
		Y:     round.key.EDDSAPub.Y(),

		// Verify the signature using Poseidon hash for the message
	}
	poseidonHashBytes := round.data.M
	if err != nil {
		return round.WrapError(fmt.Errorf("poseidon hash computation failed during verification: %v", err))
	}

	ok := edwards.Verify(&pk, poseidonHashBytes, round.temp.r, s)
	if !ok {
		return round.WrapError(fmt.Errorf("poseidon-based signature verification failed"))
	}
	round.end <- round.data

	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
