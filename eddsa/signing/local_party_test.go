// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"encoding/hex"
	"fmt"
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

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
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

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)
				R := parties[0].temp.r

				// BEGIN check s correctness
				sumS := parties[0].temp.si
				for i, p := range parties {
					if i == 0 {
						continue
					}

					var tmpSumS [32]byte
					edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), p.temp.si)
					sumS = &tmpSumS
				}
				fmt.Printf("S: %s\n", encodedBytesToBigInt(sumS).String())
				fmt.Printf("R: %s\n", R.String())
				// END check s correctness

				// BEGIN Poseidon-based EDDSA verify
				// BEGIN Poseidon-based EDDSA verify (custom verification)
				poseidonHash, err := poseidon.HashBytes(msg.Bytes())
				if err != nil {
					t.Fatalf("Poseidon hashing failed: %v", err)
				}

				// Reduce the poseidon hash mod the group order `L`
				order := tss.Edwards().Params().N
				h := new(big.Int).Mod(new(big.Int).SetBytes(poseidonHash.Bytes()), order)

				// Extract R, S from the signature
				newSig, err := edwards.ParseSignature(parties[0].data.Signature)
				if err != nil {
					t.Fatalf("Error parsing signature: %v", err)
				}

				// Reconstruct R as a point. The `R` in an EdDSA signature is a compressed point.
				// Convert `newSig.R` back to 32-byte form and parse as a public key.
				RBytes := bigIntToFixedBytes(newSig.R, 32)
				RPoint, err := edwards.ParsePubKey(RBytes)
				if err != nil {
					t.Fatalf("Failed to parse R as a point: %v", err)
				}

				// A is the public key of the signer
				pkX, pkY := keys[0].EDDSAPub.X(), keys[0].EDDSAPub.Y()
				APoint := &edwards.PublicKey{Curve: tss.Edwards(), X: pkX, Y: pkY}

				// s is a scalar
				s := new(big.Int).Set(newSig.S)

				// Compute s·B (B is the base point)
				sB_x, sB_y := tss.Edwards().ScalarBaseMult(s.Bytes())

				// Compute h·A
				hA_x, hA_y := tss.Edwards().ScalarMult(APoint.X, APoint.Y, h.Bytes())

				// Compute R + hA
				RplusHAtX, RplusHAtY := tss.Edwards().Add(RPoint.X, RPoint.Y, hA_x, hA_y)

				// Check equality: R + hA == s·B ?
				if RplusHAtX.Cmp(sB_x) == 0 && RplusHAtY.Cmp(sB_y) == 0 {
					t.Log("Poseidon-based EDDSA signing test done (custom verification).")
				} else {
					t.Fatal("Poseidon-based EDDSA verify failed (custom verification).")
				}

			}
		}
	}
}

func TestE2EConcurrentWithLeadingZeroInMSG(t *testing.T) {
	setUp("info")

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
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

	msg, _ := hex.DecodeString("00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5")
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), threshold)
		P := NewLocalParty(new(big.Int).SetBytes(msg), params, keys[i], outCh, endCh, len(msg)).(*LocalParty)
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
				sumS := parties[0].temp.si
				for i, p := range parties {
					if i == 0 {
						continue
					}

					var tmpSumS [32]byte
					edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), p.temp.si)
					sumS = &tmpSumS
				}
				fmt.Printf("S: %s\n", encodedBytesToBigInt(sumS).String())
				fmt.Printf("R: %s\n", R.String())
				// END check s correctness

				// BEGIN Poseidon-based EDDSA verify
				poseidonHash, err := poseidon.HashBytes(msg)
				if err != nil {
					t.Fatalf("Poseidon hashing failed: %v", err)
				}

				pkX, pkY := keys[0].EDDSAPub.X(), keys[0].EDDSAPub.Y()
				pk := edwards.PublicKey{
					Curve: tss.Edwards(),
					X:     pkX,
					Y:     pkY,
				}

				newSig, err := edwards.ParseSignature(parties[0].data.Signature)
				if err != nil {
					println("new sig error, ", err.Error())
				}

				ok := edwards.Verify(&pk, poseidonHash.Bytes(), newSig.R, newSig.S)
				assert.True(t, ok, "Poseidon-based EDDSA verify must pass")
				t.Log("Poseidon-based EDDSA signing test done.")
				// END Poseidon-based EDDSA verify

				break signing
			}
		}
	}
}

// Correct conversion of R to a fixed-size [32]byte array
func TestPoseidonE2EConcurrent(t *testing.T) {
	setUp("info")

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
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

	// Example message
	msg := big.NewInt(200)

	// Initialize parties
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

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)

				// Retrieve computed R and s from the first party
				R := parties[0].temp.r
				sumS := parties[0].temp.si

				// Combine `s` values from all parties
				for i, p := range parties {
					if i == 0 {
						continue
					}
					var tmpSumS [32]byte
					edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), p.temp.si)
					sumS = &tmpSumS
				}
				t.Logf("Intermediate S: %x", encodedBytesToBigInt(sumS).Bytes())
				t.Logf("Intermediate R: %x", R.Bytes())

				// BEGIN: Poseidon-specific EDDSA signature verification
				// Convert R to a fixed-size [32]byte
				var RBytes [32]byte
				copy(RBytes[:], R.Bytes())

				// Convert public key to bytes manually
				pkX, pkY := keys[0].EDDSAPub.X(), keys[0].EDDSAPub.Y()
				pubKeyBytes := append(pkX.Bytes(), pkY.Bytes()...)

				// Recompute Poseidon hash
				poseidonInputs := [][]byte{RBytes[:], pubKeyBytes, msg.Bytes()}
				poseidonHash, err := poseidon.HashBytes(flattenByteSlices(poseidonInputs))
				assert.NoError(t, err, "Poseidon hashing should succeed")

				var reducedHash [32]byte
				copy(reducedHash[:], poseidonHash.Bytes())

				// Public key reconstruction
				pk := edwards.PublicKey{
					Curve: tss.Edwards(),
					X:     pkX,
					Y:     pkY,
				}

				// Verify signature
				signatureR := encodedBytesToBigInt(&RBytes)
				signatureS := encodedBytesToBigInt(sumS)
				signature := &edwards.Signature{
					R: signatureR,
					S: signatureS,
				}

				ok := edwards.Verify(&pk, reducedHash[:], signature.R, signature.S)
				assert.True(t, ok, "Poseidon-based EDDSA verification must pass")
				t.Log("Poseidon-based EDDSA signing test passed.")
				// END: Poseidon-specific EDDSA signature verification

				break signing
			}
		}
	}
}
