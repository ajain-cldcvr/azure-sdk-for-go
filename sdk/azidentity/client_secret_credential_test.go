// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const (
	tenantID                 = "expected-tenant"
	badTenantID              = "bad_tenant"
	clientID                 = "expected-client-id"
	secret                   = "secret"
	scope                    = "https://storage.azure.com/.default"
	defaultTestAuthorityHost = "login.microsoftonline.com"
)

func TestClientSecretCredential_InvalidTenantID(t *testing.T) {
	cred, err := NewClientSecretCredential(badTenantID, clientID, secret, nil)
	if err == nil {
		t.Fatal("Expected an error but received none")
	}
	if cred != nil {
		t.Fatalf("Expected a nil credential value. Received: %v", cred)
	}
}

func TestClientSecretCredential_GetTokenSuccess(t *testing.T) {
	cred, err := NewClientSecretCredential(tenantID, clientID, secret, nil)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakeConfidentialClient{}
	_, err = cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		t.Fatalf("Expected an empty error but received: %v", err)
	}
}

func TestClientSecretCredential_Live(t *testing.T) {
	opts, stop := initRecording(t)
	defer stop()
	o := ClientSecretCredentialOptions{ClientOptions: opts}
	cred, err := NewClientSecretCredential(liveSP.tenantID, liveSP.clientID, liveSP.secret, &o)
	if err != nil {
		t.Fatalf("failed to construct credential: %v", err)
	}
	tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}
	if tk.Token == "" {
		t.Fatalf("GetToken returned an invalid token")
	}
	if tk.ExpiresOn.Before(time.Now().UTC()) {
		t.Fatalf("GetToken returned an invalid expiration time")
	}
	_, actual := tk.ExpiresOn.Zone()
	_, expected := time.Now().UTC().Zone()
	if actual != expected {
		t.Fatal("ExpiresOn isn't UTC")
	}
	tk2, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}
	if tk2.Token != tk.Token || tk2.ExpiresOn.After(tk.ExpiresOn) {
		t.Fatal("expected a cached token")
	}
}

func TestClientSecretCredential_InvalidSecretLive(t *testing.T) {
	opts, stop := initRecording(t)
	defer stop()
	o := ClientSecretCredentialOptions{ClientOptions: opts}
	cred, err := NewClientSecretCredential(liveSP.tenantID, liveSP.clientID, "invalid secret", &o)
	if err != nil {
		t.Fatalf("failed to construct credential: %v", err)
	}
	tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if tk != nil {
		t.Fatal("GetToken returned a token")
	}
	var e AuthenticationFailedError
	if !errors.As(err, &e) {
		t.Fatal("expected AuthenticationFailedError")
	}
	if e.RawResponse() == nil {
		t.Fatal("expected RawResponse() to return a non-nil *http.Response")
	}
}
