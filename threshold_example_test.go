package soroauth_test

import (
	"context"
	"fmt"
	"github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// ExampleThresholdSigner_success demonstrates a successful signature using a threshold signer
// with enough participants contributing valid shares.
func ExampleThresholdSigner_success() {
	account := "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
	partyA := "GBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWK2L"
	partyB := "GCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=================WK2M"

	signer, err := soroauth.NewThresholdSigner(account, 2, partyA, partyB)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	ctx := context.Background()
	round, err := signer.Begin(ctx)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	// Fixed test share 1 (deterministic 32-byte prefix + data)
	share1 := make([]byte, 64)
	copy(share1[:32], []byte(partyA))
	share1[32] = 0x42

	// Fixed test share 2
	share2 := make([]byte, 64)
	copy(share2[:32], []byte(partyB))
	share2[32] = 0x24

	_, err = signer.Contribute(ctx, round, share1)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	accSig, err := signer.Contribute(ctx, round, share2)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	if accSig != nil && signer.IsComplete() {
		fmt.Println("Threshold met: signature produced successfully.")
	}

	// Output:
	// Threshold met: signature produced successfully.
}

// ExampleThresholdSigner_refusalBelowThreshold demonstrates that a below-threshold attempt
// refuses cleanly with no partial result.
func ExampleThresholdSigner_refusalBelowThreshold() {
	account := "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
	partyA := "GBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWK2L"
	partyB := "GCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=================WK2M"

	signer, err := soroauth.NewThresholdSigner(account, 2, partyA, partyB)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	ctx := context.Background()
	round, err := signer.Begin(ctx)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	// Only 1 share provided for a 2-of-2 (or 2-of-3) requirement
	share1 := make([]byte, 64)
	copy(share1[:32], []byte(partyA))
	share1[32] = 0x42

	res, err := signer.Contribute(ctx, round, share1)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}

	if res == nil && !signer.IsComplete() {
		fmt.Println("Refused cleanly: below threshold, no partial result produced.")
	}

	// Attempting to sign the entry directly before threshold is met fails
	preimage := xdr.HashIdPreimage{}
	var payload [32]byte
	_, signErr := signer.Sign(ctx, preimage, payload)
	if signErr != nil {
		fmt.Println("Sign failed as expected due to missing signers.")
	}

	// Output:
	// Refused cleanly: below threshold, no partial result produced.
	// Sign failed as expected due to missing signers.
}
