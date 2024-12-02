// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package test

import (
	"testing"

	"github.com/bnb-chain/tss-lib/v2/tss"
)

func SharedPartyUpdater(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	// do not send a message from this party back to itself
	if party.PartyID() == msg.GetFrom() {
		return
	}
	bz, _, err := msg.WireBytes()
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}
	pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}
	if _, err := party.Update(pMsg); err != nil {
		errCh <- err
	}
}

// CheckOk fails the test if result == false.
func CheckOk(result bool, msg string, t testing.TB) {
	t.Helper()

	if !result {
		t.Fatal(msg)
	}
}

// checkErr fails on error condition. mustFail indicates whether err is expected
// to be nil or not.
func checkErr(t testing.TB, err error, mustFail bool, msg string) {
	t.Helper()
	if err != nil && !mustFail {
		t.Fatalf("msg: %v\nerr: %v", msg, err)
	}

	if err == nil && mustFail {
		t.Fatalf("msg: %v\nerr: %v", msg, err)
	}
}

// CheckNoErr fails if err !=nil. Print msg as an error message.
func CheckNoErr(t testing.TB, err error, msg string) { t.Helper(); checkErr(t, err, false, msg) }
