// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	cmt "github.com/bnb-chain/tss-lib/v2/crypto/commitments"
	"github.com/bnb-chain/tss-lib/v2/crypto/poseidon"
	"github.com/bnb-chain/tss-lib/v2/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

// These messages were generated from Protocol Buffers definitions into eddsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message)(nil),
		(*SignRound2Message)(nil),
		(*SignRound3Message)(nil),
	}
)

// ----- //

func NewSignRound1Message(
	from *tss.PartyID,
	commitment *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message{
		Commitment: commitment.Bytes(), // Convert `*big.Int` to `[]byte`
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ----- //

func NewSignRound2Message(
	from *tss.PartyID,
	deCommitment []*big.Int, // Updated to match new input
	proof *schnorr.ZKProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	// Compute Poseidon hash for each deCommitment component
	dcBzs := make([][]byte, len(deCommitment))
	for i, dc := range deCommitment {
		poseidonHash, _ := poseidon.HashBytes(dc.Bytes()) // Assuming error handled elsewhere
		dcBzs[i] = poseidonHash.Bytes()
	}

	content := &SignRound2Message{
		DeCommitment: dcBzs,
		ProofAlphaX:  proof.Alpha.X().Bytes(),
		ProofAlphaY:  proof.Alpha.Y().Bytes(),
		ProofT:       proof.T.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound2Message) ValidateBasic() bool {
	return common.NonEmptyMultiBytes(m.DeCommitment, 3) &&
		common.NonEmptyBytes(m.ProofAlphaX) &&
		common.NonEmptyBytes(m.ProofAlphaY) &&
		common.NonEmptyBytes(m.ProofT)
}
func (m *SignRound1Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.Commitment)
}

func (m *SignRound2Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *SignRound2Message) UnmarshalZKProof(ec elliptic.Curve) (*schnorr.ZKProof, error) {
	point, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.GetProofAlphaX()),
		new(big.Int).SetBytes(m.GetProofAlphaY()))
	if err != nil {
		return nil, err
	}
	return &schnorr.ZKProof{
		Alpha: point,
		T:     new(big.Int).SetBytes(m.GetProofT()),
	}, nil
}

// ----- //

func NewSignRound3Message(
	from *tss.PartyID,
	si *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound3Message{
		S: si.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *SignRound3Message) ValidateBasic() bool {
	return common.NonEmptyBytes(m.S)
}

func (m *SignRound3Message) UnmarshalS() *big.Int {
	return new(big.Int).SetBytes(m.S)
}

func (m *SignRound1Message) ValidateBasic() bool {
	return m.Commitment != nil && common.NonEmptyBytes(m.Commitment)
}
