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

	var MBytes []byte
	if round.temp.fullBytesLen == 0 {
		MBytes = round.temp.m.Bytes()
	} else {
		mBytes := make([]byte, round.temp.fullBytesLen)
		round.temp.m.FillBytes(mBytes)
		MBytes = mBytes
	}
	round.data.M = MBytes

	pkX, pkY := round.key.EDDSAPub.X(), round.key.EDDSAPub.Y()
	pk := edwards.PublicKey{
		Curve: round.Params().EC(),
		X:     pkX,
		Y:     pkY,
	}

	// Perform Poseidon-based signature verification
	order := round.Params().EC().Params().N

	// Convert R to 32-byte array
	RBytes := bigIntToFixedBytes(round.temp.r, 32)

	// Convert public key to bytes
	pkXBytes := pkX.Bytes()
	pkYBytes := pkY.Bytes()
	pubKeyBytes := append(pkXBytes, pkYBytes...)

	// Recompute Poseidon hash h = Poseidon(R || A || M)
	poseidonInputs := [][]byte{RBytes, pubKeyBytes, MBytes}
	poseidonHash, err := poseidon.HashBytes(flattenByteSlices(poseidonInputs))
	if err != nil {
		return round.WrapError(err)
	}

	h := new(big.Int).Mod(new(big.Int).SetBytes(poseidonHash.Bytes()), order)

	// Parse R as a point on Edwards curve
	RPoint, err := edwards.ParsePubKey(RBytes)
	if err != nil {
		return round.WrapError(err)
	}

	// Compute s·B
	sB_x, sB_y := round.Params().EC().ScalarBaseMult(s.Bytes())

	// Compute h·A
	hA_x, hA_y := round.Params().EC().ScalarMult(pk.X, pk.Y, h.Bytes())

	// Compute R + hA
	RplusHAtX, RplusHAtY := round.Params().EC().Add(RPoint.X, RPoint.Y, hA_x, hA_y)

	// Check equality: R + hA == s·B ?
	if RplusHAtX.Cmp(sB_x) != 0 || RplusHAtY.Cmp(sB_y) != 0 {
		return round.WrapError(fmt.Errorf("poseidon-based signature verification failed"))
	}

	// If we reach here, verification succeeded
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
