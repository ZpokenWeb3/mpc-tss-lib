package rsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestSignPSS(t *testing.T) {
	k := uint16(2)
	l := uint16(13)
	bitSize := 1024
	keyShares, keyMeta, err := NewKey(bitSize, k, l, nil)
	if err != nil {
		t.Logf("Error create key shares: %v", err)
		t.Fatal(err)
	}

	data := []byte("Hello, world!")
	docHash := sha256.Sum256(data)
	docPSS, err := PreparePssDocumentHash(keyMeta.PublicKey.N.BitLen(), crypto.SHA256, docHash[:], nil)
	if err != nil {
		t.Logf("Error pad hash: %v", err)
		t.Fatal(err)
	}

	sigShares := make(SigShareList, l)
	var i uint16
	for i = 0; i < l; i++ {
		sigShares[i], err = keyShares[i].Sign(docPSS, crypto.SHA256, keyMeta)
		err = sigShares[i].Verify(docPSS, keyMeta)
		if err != nil {
			t.Logf("Error sign shares: %v", err)
			t.Fatal(err)
		}

	}
	signature, err := sigShares.Join(docPSS, keyMeta)
	if err != nil {
		t.Logf("Error join shares: %v", err)
		t.Fatal(err)
	}
	err = rsa.VerifyPSS(keyMeta.PublicKey, crypto.SHA256, docHash[:], signature, nil)
	if err != nil {
		t.Logf("Error verifying signature: %v", err)
		t.Fatal(err)
	}

}

func BenchmarkSigSharesGenerationPSS(b *testing.B) {
	k := uint16(3)
	l := uint16(5)
	keySize := 4096

	keyShares, keyMeta, err := NewKey(keySize, k, l, nil)
	if err != nil {
		b.Fatal(err)
	}

	data := []byte("Hello, world!")
	docHash := sha256.Sum256(data)
	docPSS, err := PreparePssDocumentHash(keyMeta.PublicKey.N.BitLen(), crypto.SHA256, docHash[:], nil)
	if err != nil {
		b.Fatal(err)
	}

	var i uint16

	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		for i = 0; i < l; i++ {
			_, err = keyShares[i].Sign(docPSS, crypto.SHA256, keyMeta)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkSigSharesCombinePSS(b *testing.B) {
	k := uint16(3)
	l := uint16(5)
	keySize := 4096

	keyShares, keyMeta, err := NewKey(keySize, k, l, nil)
	if err != nil {
		b.Fatal(err)
	}

	data := []byte("Hello, world!")
	docHash := sha256.Sum256(data)
	docPSS, err := PreparePssDocumentHash(keyMeta.PublicKey.N.BitLen(), crypto.SHA256, docHash[:], nil)
	if err != nil {
		b.Fatal(err)
	}

	sigShares := make(SigShareList, l)
	var i uint16
	for i = 0; i < l; i++ {
		sigShares[i], err = keyShares[i].Sign(docPSS, crypto.SHA256, keyMeta)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := sigShares.Join(docPSS, keyMeta)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSigSharesVerificationPSS(b *testing.B) {
	k := uint16(3)
	l := uint16(5)
	keySize := 4096

	keyShares, keyMeta, err := NewKey(keySize, k, l, nil)
	if err != nil {
		b.Fatal(err)
	}

	data := []byte("Hello, world!")
	docHash := sha256.Sum256(data)
	docPSS, err := PreparePssDocumentHash(keyMeta.PublicKey.N.BitLen(), crypto.SHA256, docHash[:], nil)
	if err != nil {
		b.Fatal(err)
	}

	sigShares := make(SigShareList, l)
	var i uint16
	for i = 0; i < l; i++ {
		sigShares[i], err = keyShares[i].Sign(docPSS, crypto.SHA256, keyMeta)
		if err != nil {
			b.Fatal(err)
		}
	}

	signature, err := sigShares.Join(docPSS, keyMeta)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := rsa.VerifyPSS(keyMeta.PublicKey, crypto.SHA256, docHash[:], signature, nil); err != nil {
			b.Fatal(err)
		}
	}
}
