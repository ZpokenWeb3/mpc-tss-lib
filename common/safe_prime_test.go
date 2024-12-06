// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"context"
	"crypto/rand"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_getSafePrime(t *testing.T) {
	prime := new(big.Int).SetInt64(5)
	sPrime := getSafePrime(prime)
	assert.True(t, sPrime.ProbablyPrime(50))
}

func Test_getSafePrime_Bad(t *testing.T) {
	prime := new(big.Int).SetInt64(12)
	sPrime := getSafePrime(prime)
	assert.False(t, sPrime.ProbablyPrime(50))
}

func Test_Validate(t *testing.T) {
	prime := new(big.Int).SetInt64(5)
	sPrime := getSafePrime(prime)
	sgp := &GermainSafePrime{prime, sPrime}
	assert.True(t, sgp.Validate())
}

func Test_Validate_Bad(t *testing.T) {
	prime := new(big.Int).SetInt64(12)
	sPrime := getSafePrime(prime)
	sgp := &GermainSafePrime{prime, sPrime}
	assert.False(t, sgp.Validate())
}

func TestGetRandomGermainPrimeConcurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	sgps, err := GetRandomSafePrimesConcurrent(ctx, 1024, 2, runtime.NumCPU(), rand.Reader)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(sgps))
	for _, sgp := range sgps {
		assert.NotNil(t, sgp)
		assert.True(t, sgp.Validate())
	}
}

func Test_ValidateWithPoseidonHash(t *testing.T) {
	prime := new(big.Int).SetInt64(5)
	sPrime := getSafePrime(prime)

	inputs := []*big.Int{prime, sPrime}
	hash, err := PoseidonHashInt(inputs...)
	assert.NoError(t, err)

	sgp := &GermainSafePrime{prime, sPrime}
	isValid := sgp.Validate() && hash.BitLen() > 0
	assert.True(t, isValid)
}

func Test_GeneratePrimeWithPoseidon(t *testing.T) {
	// Generate a Poseidon hash
	inputs := []*big.Int{
		big.NewInt(123),
		big.NewInt(456),
	}
	hash, err := PoseidonHashInt(inputs...)
	assert.NoError(t, err)

	// Generate q and p = 2q + 1, ensuring both are primes
	var q, safePrime *big.Int
	for {
		// Ensure the Poseidon hash is converted into a prime
		q = new(big.Int).Set(hash)
		if q.ProbablyPrime(50) {
			safePrime = getSafePrime(q)
			if safePrime.ProbablyPrime(50) {
				break // Found valid q and p
			}
		}
		// Increment the hash to find the next valid q
		hash.Add(hash, big.NewInt(1))
	}

	// Verify results
	t.Logf("Generated q: %v", q)
	t.Logf("Generated safe prime: %v", safePrime)
	assert.True(t, q.ProbablyPrime(50), "q should be prime")
	assert.True(t, safePrime.ProbablyPrime(50), "Safe prime should pass primality test")
}
