package pkg

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

func hexToBytes(src string) []byte {
	dst := make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(dst, []byte(src))
	if err != nil {
		panic(err)
	}

	return dst[:n]
}

func TestAddScalars(test *testing.T) {
	// each player generates secret Ri
	r1 := make([]byte, 32)
	_, err := rand.Read(r1)
	require.NoError(test, err)

	r2 := make([]byte, 32)
	_, err = rand.Read(r2)
	require.NoError(test, err)

	r3 := make([]byte, 32)
	_, err = rand.Read(r3)
	require.NoError(test, err)

	// each player split secret per t,n, Rij
	shares1 := DealShares(r1, 2, 3)
	shares2 := DealShares(r2, 2, 3)
	shares3 := DealShares(r3, 2, 3)

	// each player sends Sij to corresponding other player
	// players add all Sij to form their working secret
	s1 := AddScalars([]Scalar{shares1[0], shares2[0], shares3[0]})
	s2 := AddScalars([]Scalar{shares1[1], shares2[1], shares3[1]})
	s3 := AddScalars([]Scalar{shares1[2], shares2[2], shares3[2]})

	// original secret from random parts
	secret := AddScalars([]Scalar{r1, r2, r3})

	{
		// combinding s1...s3 should result in the same original secret
		recombined := CombineShares(3, []int{1, 2, 3}, [][]byte{s1, s2, s3})
		require.Equal(test, secret, recombined)
	}
	{
		recombined := CombineShares(3, []int{1, 2}, [][]byte{s1, s2})
		require.Equal(test, secret, recombined)
	}
	{
		recombined := CombineShares(3, []int{2, 3}, [][]byte{s2, s3})
		require.Equal(test, secret, recombined)
	}
	{
		recombined := CombineShares(3, []int{1, 3}, [][]byte{s1, s3})
		require.Equal(test, secret, recombined)
	}
}

func TestAddElements(test *testing.T) {
	s1 := make([]byte, 32)
	s2 := make([]byte, 32)
	s3 := make([]byte, 32)

	rand.Read(s1)
	rand.Read(s2)
	rand.Read(s3)

	recombinedSecret := AddScalars([]Scalar{s1, s2, s3})

	// we get the public key directly from the expanded secret
	recombinedPublic := ScalarMultiplyBase(recombinedSecret)

	pub1 := ScalarMultiplyBase(s1)
	pub2 := ScalarMultiplyBase(s2)
	pub3 := ScalarMultiplyBase(s3)

	addedPublic := AddElements([]Element{pub1, pub2, pub3})

	require.Equal(test, recombinedPublic, addedPublic)
}

func TestValid2Of3(test *testing.T) {
	message := []byte("Hello World!")

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(test, err)

	shares := DealShares(ExpandSecret(privateKey.Seed()), 2, 3)

	ephPublicKey, ephPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(test, err)

	ephShares := DealShares(ExpandSecret(ephPrivateKey.Seed()), 2, 3)

	shareSig1 := SignWithShare(message, shares[0], ephShares[0], publicKey, ephPublicKey)
	shareSig2 := SignWithShare(message, shares[1], ephShares[1], publicKey, ephPublicKey)
	shareSig3 := SignWithShare(message, shares[2], ephShares[2], publicKey, ephPublicKey)

	{
		combinedSig := CombineShares(3, []int{1, 2, 3}, [][]byte{shareSig1, shareSig2, shareSig3})
		signature := append(ephPublicKey, combinedSig...)
		require.True(test, ed25519.Verify(publicKey, message, signature[:]), "Invalid Signature for signer [1,2,3]")
	}

	{
		combinedSig := CombineShares(3, []int{1, 2}, [][]byte{shareSig1, shareSig2})
		signature := append(ephPublicKey, combinedSig...)
		require.True(test, ed25519.Verify(publicKey, message, signature[:]), "Invalid Signature for signer [1,2]")
	}

	{
		combinedSig := CombineShares(3, []int{2, 3}, [][]byte{shareSig2, shareSig3})
		signature := append(ephPublicKey, combinedSig...)
		require.True(test, ed25519.Verify(publicKey, message, signature[:]), "Invalid Signature for signer [2,3]")
	}

	{
		combinedSig := CombineShares(3, []int{1, 3}, [][]byte{shareSig1, shareSig3})
		signature := append(ephPublicKey, combinedSig...)
		require.True(test, ed25519.Verify(publicKey, message, signature[:]), "Invalid Signature for signer [1,3]")
	}

	{
		combinedSig := CombineShares(3, []int{1}, [][]byte{shareSig1})
		signature := append(ephPublicKey, combinedSig...)
		require.False(test, ed25519.Verify(publicKey, message, signature[:]), "Signature should not be valid")
	}
}

// manually forces the final secret in CombineShares to be < 32 bytes in length
// Tests that the reverse and copy into final signature happen in the correct order
func TestCombine(test *testing.T) {
	message := []byte("Hello World!")

	publicKey := hexToBytes("f4150e597f1f7fdde0e0c174b6b9f9191ce7e0f28b2a14a6c414d7ed9ec7e756")
	ephPublicKey := hexToBytes("66724ac3ddf63cca83994496be07bc7be855283a7b4dde6bcd292c7f80daec2a")

	shareSig1 := hexToBytes("75199ff37d42acc04cc5e2ed076e8dd3529382395b78f55ad0da80fbe331c809")
	shareSig2 := hexToBytes("f79c539d0a0fe711cf12ebb67eee602893bfdf180910a9c1deada79ce1371c03")

	{
		combinedSig := CombineShares(3, []int{1, 2}, [][]byte{shareSig1, shareSig2})
		signature := append(ephPublicKey, combinedSig...)
		if !ed25519.Verify(publicKey, message, signature[:]) {
			test.Error("Invalid Signature for signer [1,2]")
		}
	}
}

// Test that no single signer produces a valid signature
func TestInvalid1Of3(test *testing.T) {
	message := []byte("Hello World!")

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(test, err)

	shares := DealShares(privateKey.Seed(), 2, 3)

	ephPublicKey, ephPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(test, err)

	ephShares := DealShares(ephPrivateKey.Seed(), 2, 3)

	shareSig0 := SignWithShare(message, shares[0], ephShares[0], publicKey, ephPublicKey)
	shareSig1 := SignWithShare(message, shares[1], ephShares[1], publicKey, ephPublicKey)
	shareSig2 := SignWithShare(message, shares[2], ephShares[2], publicKey, ephPublicKey)

	{
		combinedSig := CombineShares(3, []int{1}, [][]byte{shareSig0})
		signature := append(ephPublicKey, combinedSig...)
		if ed25519.Verify(publicKey, message, signature[:]) {
			test.Error("Incorrectly accepted signature")
		}

		{
			signature := append(ephPublicKey, shareSig0...)
			if ed25519.Verify(publicKey, message, signature[:]) {
				test.Error("Incorrectly accepted signature")
			}
		}

		{
			signature := append(ephPublicKey, shareSig0...)
			if ed25519.Verify(publicKey, message, signature[:]) {
				test.Error("Incorrectly accepted signature")
			}
		}
	}

	{
		combinedSig := CombineShares(3, []int{2}, [][]byte{shareSig1})
		signature := append(ephPublicKey, combinedSig...)
		if ed25519.Verify(publicKey, message, signature[:]) {
			test.Error("Incorrectly accepted signature")
		}
	}

	{
		combinedSig := CombineShares(3, []int{3}, [][]byte{shareSig2})
		signature := append(ephPublicKey, combinedSig...)
		if ed25519.Verify(publicKey, message, signature[:]) {
			test.Error("Incorrectly accepted signature")
		}
	}
}
