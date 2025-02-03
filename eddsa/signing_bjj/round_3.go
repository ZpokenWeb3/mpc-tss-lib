// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing_bjj

import (
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v2/tss"
	iden3bjj "github.com/iden3/go-iden3-crypto/babyjub"
	iden3poseidon "github.com/iden3/go-iden3-crypto/poseidon"
)

func (round *round3) Start() *tss.Error {

	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	round.number = 3
	round.started = true
	round.resetOK()

	i := round.PartyID().Index

	// 1. init R
	riB := crypto.ScalarBaseMult(round.Params().EC(), round.temp.ri)
	riB_iden3 := iden3bjj.Point{
		X: riB.X(),
		Y: riB.Y(),
	}
	if !riB_iden3.InCurve() {
		fmt.Printf("\n Point is not on curve: %d %d \n", riB_iden3.X, riB_iden3.Y)
	}
	R := riB_iden3.Projective()

	// 2-6. compute R
	for j, Pj := range round.Parties().IDs() {
		if j == i {
			continue
		}
		ContextJ := common.AppendBigIntToBytesSlice(round.temp.ssid, big.NewInt(int64(j)))
		msg := round.temp.signRound2Messages[j]
		r2msg := msg.Content().(*SignRound2Message)
		cmtDeCmt := commitments.HashCommitDecommit{C: round.temp.cjs[j], D: r2msg.UnmarshalDeCommitment()}
		ok, coordinates := cmtDeCmt.DeCommit()
		if !ok {
			return round.WrapError(errors.New("de-commitment verify failed"))
		}
		if len(coordinates) != 2 {
			return round.WrapError(errors.New("length of de-commitment should be 2"))
		}
		Rj, err := crypto.NewECPoint(round.Params().EC(), coordinates[0], coordinates[1])
		if err != nil {
			return round.WrapError(errors.Wrapf(err, "NewECPoint(Rj)"), Pj)
		}
		Rj = Rj.EightInvEight()
		proof, err := r2msg.UnmarshalZKProof(round.Params().EC())
		if err != nil {
			return round.WrapError(errors.New("failed to unmarshal Rj proof"), Pj)
		}
		ok = proof.Verify(ContextJ, Rj)
		if !ok {
			return round.WrapError(errors.New("failed to prove Rj"), Pj)
		}
		Rj_iden3 := iden3bjj.Point{
			X: Rj.X(),
			Y: Rj.Y(),
		}
		R = iden3bjj.NewPoint().Projective().Add(R, Rj_iden3.Projective())
		if !R.Affine().InCurve() {
			fmt.Printf("\n Point is not on curve: %d %d\n", R.Affine().X, R.Affine().Y)
		}
	}

	R_compress := R.Affine().Compress() // little-endian
	hmInput := []*big.Int{R.Affine().X, R.Affine().Y, round.key.EDDSAPub.X(), round.key.EDDSAPub.Y(), round.temp.m}
	hm, err := iden3poseidon.Hash(hmInput) // hm = H1(8*R.x, 8*R.y, A.x, A.y, msg)
	if err != nil {
		fmt.Printf("\n Error hashing %e: \n", err)
	}

	wi_8 := new(big.Int).Lsh(round.temp.wi, 3) // 8 * w_i
	S_i := new(big.Int).Mul(hm, wi_8)
	S_i = new(big.Int).Add(round.temp.ri, S_i)
	S_i = new(big.Int).Mod(S_i, round.Params().EC().Params().N)

	// 9. store r3 message pieces
	si := BigIntLEBytes(S_i) // little-endian
	round.temp.si = &si
	round.temp.r = SetBigIntFromLEBytes(new(big.Int), R_compress[:])

	// 10. broadcast si to other parties
	r3msg := NewSignRound3Message(round.PartyID(), S_i)
	round.temp.signRound3Messages[round.PartyID().Index] = r3msg
	round.out <- r3msg

	return nil
}

func (round *round3) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound3Messages {
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

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
