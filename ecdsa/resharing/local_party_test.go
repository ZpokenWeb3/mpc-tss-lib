// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	. "github.com/bnb-chain/tss-lib/v2/ecdsa/resharing"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
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

func TestE2EConcurrent(t *testing.T) {
	setUp("info")

	const iterations = 10
	var iterationDurations []time.Duration // Slice to store durations of each iteration
	var totalDuration time.Duration

	for iter := 1; iter <= iterations; iter++ {
		t.Logf("Running iteration %d of TestE2EConcurrent", iter)

		startTime := time.Now() // Start timing for this iteration

		threshold, newThreshold := testThreshold, testThreshold

		// PHASE: load keygen fixtures
		firstPartyIdx, extraParties := 1, 1
		oldKeys, oldPIDs, err := keygen.LoadKeygenTestFixtures(testThreshold+1+extraParties+firstPartyIdx, firstPartyIdx)
		assert.NoError(t, err, "should load keygen fixtures")

		// PHASE: resharing
		oldP2PCtx := tss.NewPeerContext(oldPIDs)
		fixtures, _, err := keygen.LoadKeygenTestFixtures(testParticipants)
		if err != nil {
			common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		}
		newPIDs := tss.GenerateTestPartyIDs(testParticipants)
		newP2PCtx := tss.NewPeerContext(newPIDs)
		newPCount := len(newPIDs)

		oldCommittee := make([]*LocalParty, 0, len(oldPIDs))
		newCommittee := make([]*LocalParty, 0, newPCount)
		bothCommitteesPax := len(oldCommittee) + len(newCommittee)

		errCh := make(chan *tss.Error, bothCommitteesPax)
		outCh := make(chan tss.Message, bothCommitteesPax)
		endCh := make(chan *keygen.LocalPartySaveData, bothCommitteesPax)

		updater := test.SharedPartyUpdater

		// Initialize old parties
		for j, pID := range oldPIDs {
			params := tss.NewReSharingParameters(tss.S256(), oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold)
			P := NewLocalParty(params, oldKeys[j], outCh, endCh).(*LocalParty)
			oldCommittee = append(oldCommittee, P)
		}
		// Initialize new parties
		for j, pID := range newPIDs {
			params := tss.NewReSharingParameters(tss.S256(), oldP2PCtx, newP2PCtx, pID, testParticipants, threshold, newPCount, newThreshold)
			params.SetNoProofMod()
			params.SetNoProofFac()
			save := keygen.NewLocalPartySaveData(newPCount)
			if j < len(fixtures) && len(newPIDs) <= len(fixtures) {
				save.LocalPreParams = fixtures[j].LocalPreParams
			}
			P := NewLocalParty(params, save, outCh, endCh).(*LocalParty)
			newCommittee = append(newCommittee, P)
		}

		// Start resharing
		for _, P := range newCommittee {
			go func(P *LocalParty) {
				if err := P.Start(); err != nil {
					errCh <- err
				}
			}(P)
		}
		for _, P := range oldCommittee {
			go func(P *LocalParty) {
				if err := P.Start(); err != nil {
					errCh <- err
				}
			}(P)
		}

		newKeys := make([]keygen.LocalPartySaveData, len(newCommittee))
		endedOldCommittee := 0
		var reSharingEnded int32
	resharingLoop:
		for {
			select {
			case err := <-errCh:
				common.Logger.Errorf("Error: %s", err)
				assert.FailNow(t, err.Error())
				return

			case msg := <-outCh:
				dest := msg.GetTo()
				if dest == nil {
					t.Fatal("did not expect a msg to have a nil destination during resharing")
				}
				if msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
					for _, destP := range dest[:len(oldCommittee)] {
						go updater(oldCommittee[destP.Index], msg, errCh)
					}
				}
				if !msg.IsToOldCommittee() || msg.IsToOldAndNewCommittees() {
					for _, destP := range dest {
						go updater(newCommittee[destP.Index], msg, errCh)
					}
				}

			case save := <-endCh:
				if save.Xi != nil {
					index, err := save.OriginalIndex()
					assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
					newKeys[index] = *save
				} else {
					endedOldCommittee++
				}
				atomic.AddInt32(&reSharingEnded, 1)
				if atomic.LoadInt32(&reSharingEnded) == int32(len(oldCommittee)+len(newCommittee)) {
					assert.Equal(t, len(oldCommittee), endedOldCommittee)
					break resharingLoop
				}
			}
		}

		// Record time for this iteration
		elapsed := time.Since(startTime)
		iterationDurations = append(iterationDurations, elapsed)
		totalDuration += elapsed
		t.Logf("Iteration %d completed in %.2f seconds", iter, elapsed.Seconds())
	}

	// Calculate average duration
	averageDuration := totalDuration / time.Duration(iterations)
	t.Logf("Average time taken for resharing across %d iterations: %.2f seconds", iterations, averageDuration.Seconds())

	// Log each iteration duration
	for i, duration := range iterationDurations {
		t.Logf("Iteration %d duration: %.2f seconds", i+1, duration.Seconds())
	}
}
