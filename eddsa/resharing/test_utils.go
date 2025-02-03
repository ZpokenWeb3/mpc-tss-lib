package resharing

import (
	"github.com/bnb-chain/tss-lib/v2/test"
)

const (
	// To change these parameters, you must first delete the text fixture files in test/_fixtures/ and then run the keygen test alone.
	// Then the signing and resharing tests will work with the new n, t configuration using the newly written fixture files.
	TestParticipants = test.TestParticipants
	TestThreshold    = test.TestParticipants / 2
)
