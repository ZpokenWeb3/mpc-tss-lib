// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"encoding/hex"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/agl/ed25519/edwards25519"
	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto/poseidon"
	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}

	// only for test
	tss.SetCurve(tss.Edwards())
}

func TestE2EConcurrent(t *testing.T) {
	setUp("info")

	threshold := testThreshold
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(threshold+1, testParticipants)
	assert.NoError(t, err)
	assert.Equal(t, threshold+1, len(keys))
	assert.Equal(t, threshold+1, len(signPIDs))

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200)
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), threshold)
		P := NewLocalParty(msg, params, keys[i], outCh, endCh).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32

signing:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case sigData := <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)

				// Combine all s_i
				sumS := parties[0].temp.si
				for i, p := range parties {
					if i == 0 {
						continue
					}
					var tmpSumS [32]byte
					edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), p.temp.si)
					sumS = &tmpSumS
				}

				// Custom Poseidon-based EDDSA verification
				order := tss.Edwards().Params().N
				poseidonHash, err := poseidon.HashBytes(msg.Bytes())
				assert.NoError(t, err, "Poseidon hashing failed")

				h := new(big.Int).Mod(new(big.Int).SetBytes(poseidonHash.Bytes()), order)

				// Extract signature parts
				RBytes := sigData.Signature[:32]
				SBytes := sigData.Signature[32:]

				RPoint, err := edwards.ParsePubKey(RBytes)
				assert.NoError(t, err, "Failed to parse R as a point")

				pkX, pkY := keys[0].EDDSAPub.X(), keys[0].EDDSAPub.Y()
				APoint := &edwards.PublicKey{Curve: tss.Edwards(), X: pkX, Y: pkY}

				s := new(big.Int).SetBytes(SBytes)
				sB_x, sB_y := tss.Edwards().ScalarBaseMult(s.Bytes())
				hA_x, hA_y := tss.Edwards().ScalarMult(APoint.X, APoint.Y, h.Bytes())
				RplusHAtX, RplusHAtY := tss.Edwards().Add(RPoint.X, RPoint.Y, hA_x, hA_y)

				if RplusHAtX.Cmp(sB_x) == 0 && RplusHAtY.Cmp(sB_y) == 0 {
					t.Log("Poseidon-based EDDSA signing test done (custom verification).")
				} else {
					t.Fatal("Poseidon-based EDDSA verify failed (custom verification).")
				}

				break signing
			}
		}
	}
}

func TestE2EConcurrentWithLeadingZeroInMSG(t *testing.T) {
	setUp("info")

	threshold := testThreshold
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(threshold+1, testParticipants)
	assert.NoError(t, err)
	assert.Equal(t, threshold+1, len(keys))
	assert.Equal(t, threshold+1, len(signPIDs))

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msgHex := "00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5"
	msgBytes, _ := hex.DecodeString(msgHex)
	M := new(big.Int).SetBytes(msgBytes)

	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), threshold)
		P := NewLocalParty(M, params, keys[i], outCh, endCh, len(msgBytes)).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32

signing:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case sigData := <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)

				sumS := parties[0].temp.si
				for i, p := range parties {
					if i == 0 {
						continue
					}
					var tmpSumS [32]byte
					edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), p.temp.si)
					sumS = &tmpSumS
				}

				order := tss.Edwards().Params().N
				poseidonHash, err := poseidon.HashBytes(msgBytes)
				assert.NoError(t, err, "Poseidon hashing failed")

				h := new(big.Int).Mod(new(big.Int).SetBytes(poseidonHash.Bytes()), order)

				RBytes := sigData.Signature[:32]
				SBytes := sigData.Signature[32:]

				RPoint, err := edwards.ParsePubKey(RBytes)
				assert.NoError(t, err, "Failed to parse R as a point")

				pkX, pkY := keys[0].EDDSAPub.X(), keys[0].EDDSAPub.Y()
				APoint := &edwards.PublicKey{Curve: tss.Edwards(), X: pkX, Y: pkY}

				s := new(big.Int).SetBytes(SBytes)
				sB_x, sB_y := tss.Edwards().ScalarBaseMult(s.Bytes())
				hA_x, hA_y := tss.Edwards().ScalarMult(APoint.X, APoint.Y, h.Bytes())
				RplusHAtX, RplusHAtY := tss.Edwards().Add(RPoint.X, RPoint.Y, hA_x, hA_y)

				if RplusHAtX.Cmp(sB_x) == 0 && RplusHAtY.Cmp(sB_y) == 0 {
					t.Log("Poseidon-based EDDSA signing test done (custom verification).")
				} else {
					t.Fatal("Poseidon-based EDDSA verify failed (custom verification).")
				}

				break signing
			}
		}
	}
}
