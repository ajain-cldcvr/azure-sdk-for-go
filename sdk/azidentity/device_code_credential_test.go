// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/recording"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

const (
	deviceCode                   = "device_code"
	deviceCodeResponse           = `{"user_code":"test_code","device_code":"test_device_code","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":0,"message":"To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code test_code to authenticate."}`
	deviceCodeScopes             = "user.read offline_access openid profile email"
	authorizationPendingResponse = `{"error": "authorization_pending","error_description": "Authorization pending.","error_codes": [],"timestamp": "2019-12-01 19:00:00Z","trace_id": "2d091b0","correlation_id": "a999","error_uri": "https://login.contoso.com/error?code=0"}`
	expiredTokenResponse         = `{"error": "expired_token","error_description": "Token has expired.","error_codes": [],"timestamp": "2019-12-01 19:00:00Z","trace_id": "2d091b0","correlation_id": "a999","error_uri": "https://login.contoso.com/error?code=0"}`
)

func TestDeviceCodeCredential_InvalidTenantID(t *testing.T) {
	options := DeviceCodeCredentialOptions{}
	options.TenantID = badTenantID
	cred, err := NewDeviceCodeCredential(&options)
	if err == nil {
		t.Fatal("Expected an error but received none")
	}
	if cred != nil {
		t.Fatalf("Expected a nil credential value. Received: %v", cred)
	}
}

func TestDeviceCodeCredential_GetTokenSuccess(t *testing.T) {
	t.Skip("TODO: need a way to fake MSAL device code redemption")
	cred, err := NewDeviceCodeCredential(nil)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{
		ar: public.AuthResult{
			AccessToken: tokenValue,
		},
		dc: public.DeviceCode{
			Result: public.DeviceCodeResult{},
		},
	}
	tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{deviceCodeScopes}})
	if err != nil {
		t.Fatalf("Expected an empty error but received: %s", err.Error())
	}
	if tk.Token != "new_token" {
		t.Fatalf("Received an unexpected value in azcore.AccessToken.Token")
	}
}

func TestDeviceCodeCredential_GetTokenInvalidCredentials(t *testing.T) {
	cred, err := NewDeviceCodeCredential(nil)
	if err != nil {
		t.Fatalf("Unable to create credential. Received: %v", err)
	}
	cred.client = fakePublicClient{err: errors.New("invalid credentials")}
	_, err = cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{deviceCodeScopes}})
	if err == nil {
		t.Fatalf("Expected an error but did not receive one.")
	}
}

func TestDeviceCodeCredential_UserPromptError(t *testing.T) {
	expectedCtx := context.WithValue(context.Background(), "", "")
	expected := DeviceCodeMessage{UserCode: "user code", VerificationURL: "http://localhost", Message: "message"}
	success := "it worked"
	options := DeviceCodeCredentialOptions{
		ClientID: clientID,
		TenantID: tenantID,
		UserPrompt: func(ctx context.Context, m DeviceCodeMessage) error {
			if ctx != expectedCtx {
				t.Fatal("UserPrompt received unexpected Context")
			}
			if m.Message != expected.Message {
				t.Fatalf(`unexpected Message "%s"`, m.Message)
			}
			if m.UserCode != expected.UserCode {
				t.Fatalf(`unexpected UserCode "%s"`, m.UserCode)
			}
			if m.VerificationURL != expected.VerificationURL {
				t.Fatalf(`unexpected VerificationURL "%s"`, m.VerificationURL)
			}
			return errors.New(success)
		},
	}
	cred, err := NewDeviceCodeCredential(&options)
	if err != nil {
		t.Fatalf("Unable to create credential: %v", err)
	}
	cred.client = fakePublicClient{
		dc: public.DeviceCode{
			Result: public.DeviceCodeResult{
				Message:         expected.Message,
				UserCode:        expected.UserCode,
				VerificationURL: expected.VerificationURL,
			},
		},
	}
	_, err = cred.GetToken(expectedCtx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != success {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestDeviceCodeCredential_Live(t *testing.T) {
	if recording.GetRecordMode() != recording.PlaybackMode {
		t.Skip("this test requires manual recording and can't succeed in CI")
	}
	o, stop := initRecording(t)
	defer stop()
	opts := DeviceCodeCredentialOptions{TenantID: liveUser.tenantID, ClientOptions: o}
	if recording.GetRecordMode() == recording.PlaybackMode {
		opts.UserPrompt = func(ctx context.Context, m DeviceCodeMessage) error { return nil }
	}
	cred, err := NewDeviceCodeCredential(&opts)
	if err != nil {
		t.Fatal(err)
	}
	tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{liveTestScope}})
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}
	if tk.Token == "" {
		t.Fatalf("GetToken returned an invalid token")
	}
	if !tk.ExpiresOn.After(time.Now().UTC()) {
		t.Fatalf("GetToken returned an invalid expiration time")
	}
}
