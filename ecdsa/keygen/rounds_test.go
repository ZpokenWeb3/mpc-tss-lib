package keygen

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/require"
)

// Mock dependencies for the base object
func mockBase() *base {
	return &base{
		Parameters: tss.NewParameters(tss.EC(), tss.NewPeerContext(nil), nil, 0, 0),
		temp: &localTempData{
			ssidNonce: big.NewInt(12345), // Example nonce
		},
	}
}

// Test SSID generation with SHA-512/256
func TestGetSSID_SHA(t *testing.T) {
	round := mockBase()

	// Generate SSID using SHA-512/256
	ssidList := []*big.Int{
		round.EC().Params().P,
		round.EC().Params().N,
		round.EC().Params().Gx,
		round.EC().Params().Gy,
	}
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)
	ssidList = append(ssidList, big.NewInt(int64(round.number)))
	ssidList = append(ssidList, round.temp.ssidNonce)

	expectedHash := common.SHA512_256i(ssidList...).Bytes()

	ssid, err := round.getSSID(false) // Use SHA hashing
	require.NoError(t, err)
	require.Equal(t, expectedHash, ssid, "SHA-512/256 SSID does not match expected value")
}

// Test SSID generation with Poseidon
func TestGetSSID_Poseidon(t *testing.T) {
	round := mockBase()

	// Generate SSID inputs
	ssidList := []*big.Int{
		round.EC().Params().P,
		round.EC().Params().N,
		round.EC().Params().Gx,
		round.EC().Params().Gy,
	}
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)
	ssidList = append(ssidList, big.NewInt(int64(round.number)))
	ssidList = append(ssidList, round.temp.ssidNonce)

	// Reduce inputs modulo Poseidon finite field prime
	poseidonPrime, success := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	require.True(t, success, "Failed to parse Poseidon prime")
	for i, input := range ssidList {
		ssidList[i] = new(big.Int).Mod(input, poseidonPrime)
	}

	// Hash with Poseidon
	expectedHash, err := poseidon.Hash(ssidList)
	require.NoError(t, err)

	// Generate SSID using Poseidon
	ssid, err := round.getSSID(true)
	require.NoError(t, err)
	require.Equal(t, expectedHash.Bytes(), ssid, "Poseidon SSID does not match expected value")
}
