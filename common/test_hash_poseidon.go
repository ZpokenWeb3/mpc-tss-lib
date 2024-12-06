package common

import (
	"math/big"
	"testing"
)

func TestPoseidonHash(t *testing.T) {

	input1 := []byte("hello")
	input2 := []byte("world")

	hash, err := PoseidonHash(input1, input2)
	if err != nil {
		t.Fatalf("PoseidonHash() failed: %v", err)
	}

	if len(hash) == 0 {
		t.Fatalf("PoseidonHash() returned an empty hash")
	}
	t.Logf("PoseidonHash() output: %x", hash)
}

func TestPoseidonHashInt(t *testing.T) {

	input1 := big.NewInt(123)
	input2 := big.NewInt(456)

	hash, err := PoseidonHashInt(input1, input2)
	if err != nil {
		t.Fatalf("PoseidonHashInt() failed: %v", err)
	}

	if hash == nil || hash.BitLen() == 0 {
		t.Fatalf("PoseidonHashInt() returned an invalid hash")
	}
	t.Logf("PoseidonHashInt() output: %v", hash)
}

func TestPoseidonHashTagged(t *testing.T) {

	tag := []byte("poseidon-test-tag")
	input1 := big.NewInt(789)
	input2 := big.NewInt(101112)

	hash, err := PoseidonHashTagged(tag, input1, input2)
	if err != nil {
		t.Fatalf("PoseidonHashTagged() failed: %v", err)
	}

	if hash == nil || hash.BitLen() == 0 {
		t.Fatalf("PoseidonHashTagged() returned an invalid hash")
	}
	t.Logf("PoseidonHashTagged() output: %v", hash)
}
