package policy_test

import (
	"context"
	"fmt"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/policy"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func ExamplePolicy() {
	rule := policy.NewMaxAmountRule(100)
	pol := policy.New(rule)

	entry := xdr.SorobanAuthorizationEntry{}
	preimage, _ := soroauth.Preimage(entry, 1000, network.TestNetworkPassphrase)
	payload, _ := soroauth.Payload(preimage)

	err := pol.Check(context.Background(), entry, preimage, payload)
	if err != nil {
		fmt.Println("policy check refused:", err != nil)
	}

	// Output:
	// policy check refused: true
}
