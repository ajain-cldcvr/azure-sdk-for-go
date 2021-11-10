// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

func TestInteractiveBrowserCredential_InvalidTenantID(t *testing.T) {
	options := InteractiveBrowserCredentialOptions{}
	options.TenantID = badTenantID
	cred, err := NewInteractiveBrowserCredential(&options)
	if err == nil {
		t.Fatal("Expected an error but received none")
	}
	if cred != nil {
		t.Fatalf("Expected a nil credential value. Received: %v", cred)
	}
}

func TestInteractiveBrowserCredential_GetTokenSuccess(t *testing.T) {
	cred, err := NewInteractiveBrowserCredential(nil)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{
		ar: public.AuthResult{
			AccessToken: tokenValue,
			ExpiresOn:   time.Now().Add(1 * time.Hour),
		},
	}
	tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		t.Fatalf("Expected an empty error but received: %v", err)
	}
	if tk.Token != tokenValue {
		t.Fatal("Received unexpected token")
	}
}

func TestInteractiveBrowserCredential_CreateWithNilOptions(t *testing.T) {
	cred, err := NewInteractiveBrowserCredential(nil)
	if err != nil {
		t.Fatalf("Failed to create interactive browser credential: %v", err)
	}
	if cred.options.ClientID != developerSignOnClientID {
		t.Fatalf("Wrong clientID set. Expected: %s, Received: %s", developerSignOnClientID, cred.options.ClientID)
	}
	if cred.options.TenantID != organizationsTenantID {
		t.Fatalf("Wrong tenantID set. Expected: %s, Received: %s", organizationsTenantID, cred.options.TenantID)
	}
}
