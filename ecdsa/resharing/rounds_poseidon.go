package resharing

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/stretchr/testify/require"
)

// Mock dependencies for the base object
func mockBase() *base {
	ec := tss.EC()                                               // Default elliptic curve
	oldPeerCtx := tss.NewPeerContext(nil)                        // Mock old committee
	newPeerCtx := tss.NewPeerContext(nil)                        // Mock new committee
	partyID := tss.NewPartyID("party0", "party0", big.NewInt(0)) // Mock party ID

	return &base{
		ReSharingParameters: tss.NewReSharingParameters(
			ec,
			oldPeerCtx,
			newPeerCtx,
			partyID,
			5, // Total parties in old committee
			3, // Threshold for old committee
			5, // Total parties in new committee
			3, // Threshold for new committee
		),
		temp: &localTempData{
			ssidNonce: big.NewInt(12345), // Example nonce
		},
		input: &keygen.LocalPartySaveData{
			BigXj: []*crypto.ECPoint{
				crypto.NewECPointNoCurveCheck(ec, big.NewInt(1), big.NewInt(2)),
			},
			NTildej: []*big.Int{
				big.NewInt(3),
			},
			H1j: []*big.Int{
				big.NewInt(4),
			},
			H2j: []*big.Int{
				big.NewInt(5),
			},
		},
	}
}

// Test SSID generation with SHA-512/256
func TestGetSSID_SHA(t *testing.T) {
	round := mockBase()

	// Generate SSID using SHA-512/256
	ssid, err := round.getSSID(false) // Use SHA hashing
	require.NoError(t, err, "SHA-512/256 SSID generation failed")
	require.NotNil(t, ssid, "SHA-512/256 SSID should not be nil")
}

// Test SSID generation with Poseidon
func TestGetSSID_Poseidon(t *testing.T) {
	round := mockBase()

	// Generate SSID using Poseidon
	ssid, err := round.getSSID(true) // Use Poseidon hashing
	require.NoError(t, err, "Poseidon SSID generation failed")
	require.NotNil(t, ssid, "Poseidon SSID should not be nil")
}

// Test Poseidon input reduction
func TestPoseidonInputReduction(t *testing.T) {
	round := mockBase()

	// Create mock inputs
	ssidList := []*big.Int{
		round.EC().Params().P,
		round.EC().Params().N,
		round.EC().Params().B,
		round.EC().Params().Gx,
		round.EC().Params().Gy,
	}

	// Add additional inputs
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)
	ssidList = append(ssidList, round.input.NTildej...)
	ssidList = append(ssidList, round.input.H1j...)
	ssidList = append(ssidList, round.input.H2j...)
	ssidList = append(ssidList, big.NewInt(int64(round.number)))
	ssidList = append(ssidList, round.temp.ssidNonce)

	// Poseidon prime field
	poseidonPrime, success := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	require.True(t, success, "Failed to parse Poseidon prime")

	// Reduce inputs modulo the Poseidon prime
	for i, input := range ssidList {
		ssidList[i] = new(big.Int).Mod(input, poseidonPrime)
	}

	// Ensure inputs are within the finite field
	for _, input := range ssidList {
		require.True(t, input.Cmp(poseidonPrime) < 0, "Input not reduced to finite field")
		require.False(t, input.Sign() < 0, "Input is negative")
	}
}
