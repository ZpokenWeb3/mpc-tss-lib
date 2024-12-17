// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/json"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/v2/crypto/paillier"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
)

const (
	testParticipants = TestParticipants // 5
	testThreshold    = TestThreshold    // 2
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}
}

func TestStartRound1Paillier(t *testing.T) {
	setUp("debug")
	startTime := time.Now()
	pIDs := tss.GenerateTestPartyIDs(1)
	p2pCtx := tss.NewPeerContext(pIDs)
	threshold := 1
	params := tss.NewParameters(tss.EC(), p2pCtx, pIDs[0], len(pIDs), threshold)

	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	var lp *LocalParty
	out := make(chan tss.Message, len(pIDs))
	if 0 < len(fixtures) {
		lp = NewLocalParty(params, out, nil, fixtures[0].LocalPreParams).(*LocalParty)
	} else {
		lp = NewLocalParty(params, out, nil).(*LocalParty)
	}
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}
	<-out
	elapsed := time.Since(startTime) // Stop timing
	t.Logf("Time taken for Paillier modulus generation and round 1: %.2f seconds", elapsed.Seconds())
	// Paillier modulus 2048 (two 1024-bit primes)
	// round up to 256, it was used to be flaky, sometimes comes back with 1 byte less
	len1 := len(lp.data.PaillierSK.LambdaN.Bytes())
	len2 := len(lp.data.PaillierSK.PublicKey.N.Bytes())
	if len1%2 != 0 {
		len1 = len1 + (256 - (len1 % 256))
	}
	if len2%2 != 0 {
		len2 = len2 + (256 - (len2 % 256))
	}
	assert.Equal(t, 2048/8, len1)
	assert.Equal(t, 2048/8, len2)
}

func TestFinishAndSaveH1H2(t *testing.T) {
	setUp("debug")
	startTime := time.Now() // Start timing

	pIDs := tss.GenerateTestPartyIDs(1)
	p2pCtx := tss.NewPeerContext(pIDs)
	threshold := 1
	params := tss.NewParameters(tss.EC(), p2pCtx, pIDs[0], len(pIDs), threshold)

	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	var lp *LocalParty
	out := make(chan tss.Message, len(pIDs))
	if 0 < len(fixtures) {
		lp = NewLocalParty(params, out, nil, fixtures[0].LocalPreParams).(*LocalParty)
	} else {
		lp = NewLocalParty(params, out, nil).(*LocalParty)
	}
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}
	elapsed := time.Since(startTime) // Stop timing
	t.Logf("Time taken to finish and save H1, H2, and N-tilde: %.2f seconds", elapsed.Seconds())
	// RSA modulus 2048 (two 1024-bit primes)
	// round up to 256
	len1 := len(lp.data.H1j[0].Bytes())
	len2 := len(lp.data.H2j[0].Bytes())
	len3 := len(lp.data.NTildej[0].Bytes())
	if len1%2 != 0 {
		len1 = len1 + (256 - (len1 % 256))
	}
	if len2%2 != 0 {
		len2 = len2 + (256 - (len2 % 256))
	}
	if len3%2 != 0 {
		len3 = len3 + (256 - (len3 % 256))
	}
	// 256 bytes = 2048 bits
	assert.Equal(t, 256, len1, "h1 should be correct len")
	assert.Equal(t, 256, len2, "h2 should be correct len")
	assert.Equal(t, 256, len3, "n-tilde should be correct len")
	assert.NotZero(t, lp.data.H1i, "h1 should be non-zero")
	assert.NotZero(t, lp.data.H2i, "h2 should be non-zero")
	assert.NotZero(t, lp.data.NTildei, "n-tilde should be non-zero")
}

func TestBadMessageCulprits(t *testing.T) {
	setUp("debug")

	pIDs := tss.GenerateTestPartyIDs(2)
	p2pCtx := tss.NewPeerContext(pIDs)
	params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[0], len(pIDs), 1)

	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(testParticipants)
	}

	var lp *LocalParty
	out := make(chan tss.Message, len(pIDs))
	if 0 < len(fixtures) {
		lp = NewLocalParty(params, out, nil, fixtures[0].LocalPreParams).(*LocalParty)
	} else {
		lp = NewLocalParty(params, out, nil).(*LocalParty)
	}
	if err := lp.Start(); err != nil {
		assert.FailNow(t, err.Error())
	}

	badMsg, _ := NewKGRound1Message(pIDs[1], zero, &paillier.PublicKey{N: zero}, zero, zero, zero, new(dlnproof.Proof), new(dlnproof.Proof))
	ok, err2 := lp.Update(badMsg)
	t.Log(err2)
	assert.False(t, ok)
	if !assert.Error(t, err2) {
		return
	}
	assert.Equal(t, 1, len(err2.Culprits()))
	assert.Equal(t, pIDs[1], err2.Culprits()[0])
	assert.Equal(t,
		"task ecdsa-keygen, party {0,P[1]}, round 1, culprits [{1,2}]: message failed ValidateBasic: Type: binance.tsslib.ecdsa.keygen.KGRound1Message, From: {1,2}, To: all",
		err2.Error())
}

func calculateAverageDuration(total time.Duration, iterations int) time.Duration {
	if iterations == 0 {
		return 0
	}
	return total / time.Duration(iterations)
}

func TestE2EConcurrentAndSaveFixtures(t *testing.T) {
	setUp("info")

	const iterations = 10
	var totalDuration time.Duration

	for i := 1; i <= iterations; i++ {
		t.Logf("Running iteration %d of TestE2EConcurrentAndSaveFixtures", i)

		totalStart := time.Now() // Start timing for this iteration

		threshold := testThreshold
		fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
		if err != nil {
			common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
			pIDs = tss.GenerateTestPartyIDs(testParticipants)
		}

		p2pCtx := tss.NewPeerContext(pIDs)
		parties := make([]*LocalParty, 0, len(pIDs))

		errCh := make(chan *tss.Error, len(pIDs))
		outCh := make(chan tss.Message, len(pIDs))
		endCh := make(chan *LocalPartySaveData, len(pIDs))

		updater := test.SharedPartyUpdater

		// Initialize the parties
		for i := 0; i < len(pIDs); i++ {
			var P *LocalParty
			params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
			params.SetNoProofMod()
			params.SetNoProofFac()
			if i < len(fixtures) {
				P = NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*LocalParty)
			} else {
				P = NewLocalParty(params, outCh, endCh).(*LocalParty)
			}
			parties = append(parties, P)
			go func(P *LocalParty) {
				if err := P.Start(); err != nil {
					errCh <- err
				}
			}(P)
		}

		// Key generation process
		var ended int32
		keygenStart := time.Now() // Start key pair generation timing

	keygen:
		for {
			select {
			case err := <-errCh:
				common.Logger.Errorf("Error: %s", err)
				assert.FailNow(t, err.Error())
				break keygen

			case msg := <-outCh:
				dest := msg.GetTo()
				if dest == nil { // broadcast
					for _, P := range parties {
						if P.PartyID().Index == msg.GetFrom().Index {
							continue
						}
						go updater(P, msg, errCh)
					}
				} else { // point-to-point
					go updater(parties[dest[0].Index], msg, errCh)
				}

			case save := <-endCh:
				index, err := save.OriginalIndex()
				assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
				tryWriteTestFixtureFile(t, index, *save)

				atomic.AddInt32(&ended, 1)
				if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
					keygenElapsed := time.Since(keygenStart)
					t.Logf("Key pair generation completed in %.2f seconds", keygenElapsed.Seconds())
					t.Logf("Done. Received save data from %d participants", ended)
					break keygen
				}
			}
		}

		// Measure time for this iteration
		elapsed := time.Since(totalStart)
		totalDuration += elapsed
		t.Logf("Iteration %d completed in %.2f seconds", i, elapsed.Seconds())
	}

	// Calculate average execution time
	averageDuration := calculateAverageDuration(totalDuration, iterations)
	t.Logf("Average time taken for %d iterations: %.2f seconds", iterations, averageDuration.Seconds())
}

// Helper to save test fixtures
func tryWriteTestFixtureFile(t *testing.T, index int, data LocalPartySaveData) {
	fixtureFileName := makeTestFixtureFilePath(index)

	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			assert.NoErrorf(t, err, "unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			t.Fatalf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			t.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		t.Logf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
}
