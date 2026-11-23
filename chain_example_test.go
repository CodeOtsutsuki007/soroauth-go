package soroauth_test

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func ExampleNewFallbackSigner() {
	seedHash := sha256.Sum256([]byte("signer-fallback-example"))
	kp1, _ := keypair.FromRawSeed(seedHash)
	s1 := soroauth.NewEd25519Signer(kp1)

	seedHash2 := sha256.Sum256([]byte("signer-fallback-example-2"))
	kp2, _ := keypair.FromRawSeed(seedHash2)
	s2 := soroauth.NewEd25519Signer(kp2)

	chain := soroauth.NewFallbackSigner([]soroauth.Signer{s1, s2})
	_ = chain
	fmt.Println("fallback chain constructed")
	// Output:
	// fallback chain constructed
}

func ExampleNewQuorumSigner() {
	seedHash := sha256.Sum256([]byte("signer-quorum-example"))
	kp1, _ := keypair.FromRawSeed(seedHash)
	s1 := soroauth.NewEd25519Signer(kp1)

	seedHash2 := sha256.Sum256([]byte("signer-quorum-example-2"))
	kp2, _ := keypair.FromRawSeed(seedHash2)
	s2 := soroauth.NewEd25519Signer(kp2)

	chain, err := soroauth.NewQuorumSigner(2, s1, s2)
	if err != nil {
		fmt.Println(err)
		return
	}

	entry := xdr.SorobanAuthorizationEntry{}
	preimage, _ := soroauth.Preimage(entry, 1000, network.TestNetworkPassphrase)
	payload, _ := soroauth.Payload(preimage)

	_, err = chain.Sign(context.Background(), preimage, payload)
	if err != nil {
		fmt.Println("quorum not met or error:", err != nil)
	}

	// Output:
	// quorum not met or error: true
}
