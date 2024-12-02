// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"

	cmath "github.com/cloudflare/circl/math"
)

// GenerateKey generates a RSA keypair for its use in RSA threshold signatures.
// Internally, the modulus is the product of two safe primes. The time
// consumed by this function is relatively longer than the regular
// GenerateKey function from the crypto/rsa package.
func GenerateKey(random io.Reader, bits int) (*rsa.PrivateKey, error) {
	p, err := cmath.SafePrime(random, bits/2)
	if err != nil {
		return nil, err
	}

	var q *big.Int
	n := new(big.Int)
	found := false
	for !found {
		q, err = cmath.SafePrime(random, bits-p.BitLen())
		if err != nil {
			return nil, err
		}

		// check for different primes.
		if p.Cmp(q) != 0 {
			n.Mul(p, q)
			// check n has the desired bitlength.
			if n.BitLen() == bits {
				found = true
			}
		}
	}

	one := big.NewInt(1)
	pminus1 := new(big.Int).Sub(p, one)
	qminus1 := new(big.Int).Sub(q, one)
	totient := new(big.Int).Mul(pminus1, qminus1)

	priv := new(rsa.PrivateKey)
	priv.Primes = []*big.Int{p, q}
	priv.N = n
	priv.E = 65537
	priv.D = new(big.Int)
	e := big.NewInt(int64(priv.E))
	ok := priv.D.ModInverse(e, totient)
	if ok == nil {
		return nil, errors.New("public key is not coprime to phi(n)")
	}

	priv.Precompute()

	return priv, nil
}

// l or `Players`, the total number of Players.
// t, the number of corrupted Players.
// k=t+1 or `Threshold`, the number of signature shares needed to obtain a signature.

func validateParams(players, threshold uint) error {
	if players <= 1 {
		return errors.New("rsa_threshold: Players (l) invalid: should be > 1")
	}
	if threshold < 1 || threshold > players {
		return fmt.Errorf("rsa_threshold: Threshold (k) invalid: %d < 1 || %d > %d", threshold, threshold, players)
	}
	return nil
}

// Deal takes in an existing RSA private key generated elsewhere. If cache is true, cached values are stored in KeyShare taking up more memory by reducing Sign time.
// See KeyShare documentation. Multi-prime RSA keys are unsupported.
func Deal(randSource io.Reader, players, threshold uint, key *rsa.PrivateKey, cache bool) ([]KeyShare, error) {
	err := validateParams(players, threshold)

	ONE := big.NewInt(1)

	if err != nil {
		return nil, err
	}

	if len(key.Primes) != 2 {
		return nil, errors.New("multiprime rsa keys are unsupported")
	}

	p := key.Primes[0]
	q := key.Primes[1]
	e := int64(key.E)

	// p = 2p' + 1
	// q = 2q' + 1
	// p' = (p - 1)/2
	// q' = (q - 1)/2
	// m = p'q' = (p - 1)(q - 1)/4

	var pprime big.Int
	// p - 1
	pprime.Sub(p, ONE)

	// q - 1
	var m big.Int
	m.Sub(q, ONE)
	// (p - 1)(q - 1)
	m.Mul(&m, &pprime)
	// >> 2 == / 4
	m.Rsh(&m, 2)

	// de ≡ 1
	var d big.Int
	_d := d.ModInverse(big.NewInt(e), &m)

	if _d == nil {
		return nil, errors.New("rsa_threshold: no ModInverse for e in Z/Zm")
	}

	// a_0...a_{k-1}
	a := make([]*big.Int, threshold)
	// a_0 = d
	a[0] = &d

	// a_0...a_{k-1} = rand from {0, ..., m - 1}
	for i := uint(1); i <= threshold-1; i++ {
		a[i], err = rand.Int(randSource, &m)
		if err != nil {
			return nil, errors.New("rsa_threshold: unable to generate an int within [0, m)")
		}
	}

	shares := make([]KeyShare, players)

	// 1 <= i <= l
	for i := uint(1); i <= players; i++ {
		shares[i-1].Players = players
		shares[i-1].Threshold = threshold
		// Σ^{k-1}_{i=0} | a_i * X^i (mod m)
		poly := computePolynomial(threshold, a, i, &m)
		shares[i-1].si = poly
		shares[i-1].Index = i
		if cache {
			shares[i-1].get2DeltaSi(int64(players))
		}
	}

	return shares, nil
}

func calcN(p, q *big.Int) big.Int {
	// n = pq
	var n big.Int
	n.Mul(p, q)
	return n
}

// f(X) = Σ^{k-1}_{i=0} | a_i * X^i (mod m)
func computePolynomial(k uint, a []*big.Int, x uint, m *big.Int) *big.Int {
	// TODO: use Horner's method here.
	sum := big.NewInt(0)
	//  Σ^{k-1}_{i=0}
	for i := uint(0); i <= k-1; i++ {
		// X^i
		// TODO optimize: we can compute x^{n+1} from the previous x^n
		xi := int64(math.Pow(float64(x), float64(i)))
		// a_i * X^i
		prod := big.Int{}
		prod.Mul(a[i], big.NewInt(xi))
		// (mod m)
		prod.Mod(&prod, m) // while not in the spec, we are eventually modding m, so we can mod here for efficiency
		// Σ
		sum.Add(sum, &prod)
	}

	sum.Mod(sum, m)

	return sum
}
