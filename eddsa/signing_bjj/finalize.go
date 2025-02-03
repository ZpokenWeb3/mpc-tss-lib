// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing_bjj

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/tss"
	iden3bjj "github.com/iden3/go-iden3-crypto/babyjub"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	S := encodedBytesToBigInt(round.temp.si) // from little-endian array to big-endian bigInt
	for j := range round.Parties().IDs() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		r3msg := round.temp.signRound3Messages[j].Content().(*SignRound3Message)
		sj := r3msg.UnmarshalS()
		one := big.NewInt(1)
		S = new(big.Int).Mul(S, one)
		S = new(big.Int).Add(S, sj)
	}
	S = new(big.Int).Mod(S, round.Params().EC().Params().N)

	// save the signature for final output
	R_bytes := BigIntLEBytes(round.temp.r)
	S_bytes := BigIntLEBytes(S)
	round.data.Signature = append(R_bytes[:], S_bytes[:]...) // litte-endian
	round.data.R = R_bytes[:]                                // little-endian
	round.data.S = S_bytes[:]                                // big-endian

	if round.temp.fullBytesLen == 0 {
		round.data.M = round.temp.m.Bytes()
	} else {
		var mBytes = make([]byte, round.temp.fullBytesLen)
		round.temp.m.FillBytes(mBytes)
		round.data.M = mBytes
	}

	pk := iden3bjj.PublicKey{
		X: round.key.EDDSAPub.X(),
		Y: round.key.EDDSAPub.Y(),
	}

	data := new(big.Int).SetBytes(round.data.M)
	R8, err := iden3bjj.NewPoint().Decompress(R_bytes)
	if err != nil {
		fmt.Printf("\n Error decompression %e \n", err)
	}
	sig := iden3bjj.Signature{
		R8: R8,
		S:  S,
	}
	ok := pk.VerifyPoseidon(data, &sig)
	if !ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
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
