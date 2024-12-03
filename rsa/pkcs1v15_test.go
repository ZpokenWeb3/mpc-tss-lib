package rsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestSignPKCS1v15(t *testing.T) {
	// First we need to get the values of K and L from somewhere.
	k := uint16(5)
	l := uint16(13)
	keySize := 2048

	// Generate keys provides to us with a list of keyShares and the key metainformation.
	keyShares, keyMeta, err := NewKey(keySize, k, l, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Then we need to prepare the document we want to sign, so we hash it and pad it using PKCS v1.15.
	docHash := sha256.Sum256([]byte("Hello world"))
	docPKCS1, err := PrepareDocumentHash(keyMeta.PublicKey.Size(), crypto.SHA256, docHash[:])
	if err != nil {
		t.Fatal(err)
	}

	sigShares := make(SigShareList, l)
	var i uint16

	// Now we sign with at least k nodes and check immediately the signature share for consistency.
	for i = 0; i < l; i++ {
		sigShares[i], err = keyShares[i].Sign(docPKCS1, crypto.SHA256, keyMeta)
		if err != nil {
			t.Fatal(err)
		}
		if err := sigShares[i].Verify(docPKCS1, keyMeta); err != nil {
			t.Fatal(err)
		}
	}

	// Having all the signature shares we needed, we join them to create a real signature.
	signature, err := sigShares.Join(docPKCS1, keyMeta)
	if err != nil {
		t.Fatal(err)
	}

	// Finally we check the signature with Golang's crypto/rsa PKCSv1.15 verification routine.
	if err := rsa.VerifyPKCS1v15(keyMeta.PublicKey, crypto.SHA256, docHash[:], signature); err != nil {
		t.Fatal(err)
	}
}
