// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing_bjj

import (
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/ipfs/go-log"

	iden3bjj "github.com/iden3/go-iden3-crypto/babyjub"

	"github.com/bnb-chain/tss-lib/v2/babyjubjub"
	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
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
}

func TestE2EConcurrentBJJ(t *testing.T) {
	tss.SetCurve(tss.BabyJubJub())

	setUp("info")

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msg := big.NewInt(200)
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.BabyJubJub(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

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

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)
				R := parties[0].temp.r

				// BEGIN check s correctness
				S := encodedBytesToBigInt(parties[0].temp.si) // from little-endian array to big-endian bigInt
				for i, p := range parties {
					if i == 0 {
						continue
					}
					sj := encodedBytesToBigInt(p.temp.si)
					one := big.NewInt(1)
					S = new(big.Int).Mul(S, one)
					S = new(big.Int).Add(S, sj)
				}
				fmt.Printf("S: %s\n", S.String())
				fmt.Printf("R: %s\n", R.String())
				// END check s correctness

				// BEGIN EDDSA verify
				pkX, pkY := keys[0].EDDSAPub.X(), keys[0].EDDSAPub.Y()
				pk := iden3bjj.PublicKey{
					X: pkX,
					Y: pkY,
				}

				// newSig, err := edwards.ParseSignature(parties[0].data.Signature)
				newSig, err := parseSig(parties[0].data.Signature)
				if err != nil {
					println("new sig error, ", err.Error())
				}

				ok := pk.VerifyPoseidon(msg, newSig)
				assert.True(t, ok, "eddsa verify must pass")
				t.Log("EDDSA signing test done.")
				// END EDDSA verify

				break signing
			}
		}
	}
}

// parseSig parses a serialized BabyJubJub signature.
func parseSig(sigStr []byte) (*iden3bjj.Signature, error) {
	// Ensure the signature has the correct length for BabyJubJub
	if len(sigStr) != 64 {
		return nil, fmt.Errorf("bad signature size; have %v, want 64", len(sigStr))
	}

	curve := babyjubjub.BabyJubJub()
	rBytes := copyBytes(sigStr[0:32])

	R8, err := iden3bjj.NewPoint().Decompress(*rBytes)
	if err != nil {
		fmt.Printf("\n Error decompression %e \n", err)
	}

	sBytes := copyBytes(sigStr[32:64])
	s := encodedBytesToBigInt(sBytes)

	// Validate the scalar s: it must be non-zero and less than the order of the curve
	if s.Cmp(curve.N) >= 0 || s.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("s scalar is empty or larger than the order of the curve")
	}

	return &iden3bjj.Signature{R8: R8, S: s}, nil
}
