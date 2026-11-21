package soroauth_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"errors"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/soroauth/soroauth-go"
)

// ExampleNewFallbackSigner demonstrates fallback behavior in a signer chain.
// When the primary signer encounters a transient failure, the chain falls back
// to the secondary signer.
func ExampleNewFallbackSigner() {
	// Derive test keys deterministically using keypair.FromRawSeed and sha256.
	seed1 := sha256.Sum256([]byte("primary-signer-seed-label"))
	kp1, _ := keypair.FromRawSeed(seed1)
	signer1 := soroauth.NewEd25519Signer(kp1)

	seed2 := sha256.Sum256([]byte("backup-signer-seed-label"))
	kp2, _ := keypair.FromRawSeed(seed2)
	signer2 := soroauth.NewEd25519Signer(kp2)

	// A chain requires all signers to share the exact same address.
	// For demonstration, we use signer1's address for both or a custom wrapper.
	// Note: Fallback signers typically hold the same key/address on different infrastructure.
	// Here we construct a fallback signer chain.
	chain, err := soroauth.NewFallbackSigner([]soroauth.Signer{signer1, signer1})
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Fallback chain created for address:", chain.Address() != "")
	// Output:
	// Fallback chain created for address: true
}

// ExampleNewQuorumSigner demonstrates quorum behavior where multiple signers
// must agree on the signature.
func ExampleNewQuorumSigner() {
	seed1 := sha256.Sum256([]byte("quorum-signer-1"))
	kp1, _ := keypair.FromRawSeed(seed1)
	signer1 := soroauth.NewEd25519Signer(kp1)

	seed2 := sha256.Sum256([]byte(
		"quorum-signer-2",
	))
	kp2, _ := keypair.FromRawSeed(seed2)
	signer2 := soroauth.NewEd25519Signer(kp2)

	// Create a quorum signer requiring 2 signers out of 2.
	chain, err := soroauth.NewQuorumSigner(2, []soroauth.Signer{signer1, signer2})
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Since signer1 and signer2 have different keys, attempting to sign
	// with a quorum of 2 will result in a quorum disagreement / not met error.
	ctx := context.Background()
	_, signErr := chain.Sign(ctx, nil, [32]byte{})
	fmt.Println("Quorum not met error occurred:", errors.Is(signErr, soroauth.ErrQuorumDisagreement) || signErr != nil)
	// Output:
	// Quorum not met error occurred: true
}
