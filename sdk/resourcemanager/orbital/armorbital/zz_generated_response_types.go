//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armorbital

import (
	"context"
	armruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"net/http"
	"time"
)

// AvailableGroundStationsClientGetResponse contains the response from method AvailableGroundStationsClient.Get.
type AvailableGroundStationsClientGetResponse struct {
	AvailableGroundStationsClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// AvailableGroundStationsClientGetResult contains the result from method AvailableGroundStationsClient.Get.
type AvailableGroundStationsClientGetResult struct {
	AvailableGroundStation
}

// AvailableGroundStationsClientListByCapabilityResponse contains the response from method AvailableGroundStationsClient.ListByCapability.
type AvailableGroundStationsClientListByCapabilityResponse struct {
	AvailableGroundStationsClientListByCapabilityResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// AvailableGroundStationsClientListByCapabilityResult contains the result from method AvailableGroundStationsClient.ListByCapability.
type AvailableGroundStationsClientListByCapabilityResult struct {
	AvailableGroundStationListResult
}

// ContactProfilesClientCreateOrUpdatePollerResponse contains the response from method ContactProfilesClient.CreateOrUpdate.
type ContactProfilesClientCreateOrUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ContactProfilesClientCreateOrUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ContactProfilesClientCreateOrUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ContactProfilesClientCreateOrUpdateResponse, error) {
	respType := ContactProfilesClientCreateOrUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.ContactProfile)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ContactProfilesClientCreateOrUpdatePollerResponse from the provided client and resume token.
func (l *ContactProfilesClientCreateOrUpdatePollerResponse) Resume(ctx context.Context, client *ContactProfilesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ContactProfilesClient.CreateOrUpdate", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ContactProfilesClientCreateOrUpdatePoller{
		pt: pt,
	}
	resp, err := poller.Poll(ctx)
	if err != nil {
		return err
	}
	l.Poller = poller
	l.RawResponse = resp
	return nil
}

// ContactProfilesClientCreateOrUpdateResponse contains the response from method ContactProfilesClient.CreateOrUpdate.
type ContactProfilesClientCreateOrUpdateResponse struct {
	ContactProfilesClientCreateOrUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ContactProfilesClientCreateOrUpdateResult contains the result from method ContactProfilesClient.CreateOrUpdate.
type ContactProfilesClientCreateOrUpdateResult struct {
	ContactProfile
}

// ContactProfilesClientDeletePollerResponse contains the response from method ContactProfilesClient.Delete.
type ContactProfilesClientDeletePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ContactProfilesClientDeletePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ContactProfilesClientDeletePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ContactProfilesClientDeleteResponse, error) {
	respType := ContactProfilesClientDeleteResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ContactProfilesClientDeletePollerResponse from the provided client and resume token.
func (l *ContactProfilesClientDeletePollerResponse) Resume(ctx context.Context, client *ContactProfilesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ContactProfilesClient.Delete", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ContactProfilesClientDeletePoller{
		pt: pt,
	}
	resp, err := poller.Poll(ctx)
	if err != nil {
		return err
	}
	l.Poller = poller
	l.RawResponse = resp
	return nil
}

// ContactProfilesClientDeleteResponse contains the response from method ContactProfilesClient.Delete.
type ContactProfilesClientDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ContactProfilesClientGetResponse contains the response from method ContactProfilesClient.Get.
type ContactProfilesClientGetResponse struct {
	ContactProfilesClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ContactProfilesClientGetResult contains the result from method ContactProfilesClient.Get.
type ContactProfilesClientGetResult struct {
	ContactProfile
}

// ContactProfilesClientListBySubscriptionResponse contains the response from method ContactProfilesClient.ListBySubscription.
type ContactProfilesClientListBySubscriptionResponse struct {
	ContactProfilesClientListBySubscriptionResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ContactProfilesClientListBySubscriptionResult contains the result from method ContactProfilesClient.ListBySubscription.
type ContactProfilesClientListBySubscriptionResult struct {
	ContactProfileListResult
}

// ContactProfilesClientListResponse contains the response from method ContactProfilesClient.List.
type ContactProfilesClientListResponse struct {
	ContactProfilesClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ContactProfilesClientListResult contains the result from method ContactProfilesClient.List.
type ContactProfilesClientListResult struct {
	ContactProfileListResult
}

// ContactProfilesClientUpdateTagsResponse contains the response from method ContactProfilesClient.UpdateTags.
type ContactProfilesClientUpdateTagsResponse struct {
	ContactProfilesClientUpdateTagsResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ContactProfilesClientUpdateTagsResult contains the result from method ContactProfilesClient.UpdateTags.
type ContactProfilesClientUpdateTagsResult struct {
	ContactProfile
}

// ContactsClientCreatePollerResponse contains the response from method ContactsClient.Create.
type ContactsClientCreatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ContactsClientCreatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ContactsClientCreatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ContactsClientCreateResponse, error) {
	respType := ContactsClientCreateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.Contact)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ContactsClientCreatePollerResponse from the provided client and resume token.
func (l *ContactsClientCreatePollerResponse) Resume(ctx context.Context, client *ContactsClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ContactsClient.Create", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ContactsClientCreatePoller{
		pt: pt,
	}
	resp, err := poller.Poll(ctx)
	if err != nil {
		return err
	}
	l.Poller = poller
	l.RawResponse = resp
	return nil
}

// ContactsClientCreateResponse contains the response from method ContactsClient.Create.
type ContactsClientCreateResponse struct {
	ContactsClientCreateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ContactsClientCreateResult contains the result from method ContactsClient.Create.
type ContactsClientCreateResult struct {
	Contact
}

// ContactsClientDeletePollerResponse contains the response from method ContactsClient.Delete.
type ContactsClientDeletePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ContactsClientDeletePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ContactsClientDeletePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ContactsClientDeleteResponse, error) {
	respType := ContactsClientDeleteResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ContactsClientDeletePollerResponse from the provided client and resume token.
func (l *ContactsClientDeletePollerResponse) Resume(ctx context.Context, client *ContactsClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ContactsClient.Delete", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ContactsClientDeletePoller{
		pt: pt,
	}
	resp, err := poller.Poll(ctx)
	if err != nil {
		return err
	}
	l.Poller = poller
	l.RawResponse = resp
	return nil
}

// ContactsClientDeleteResponse contains the response from method ContactsClient.Delete.
type ContactsClientDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ContactsClientGetResponse contains the response from method ContactsClient.Get.
type ContactsClientGetResponse struct {
	ContactsClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ContactsClientGetResult contains the result from method ContactsClient.Get.
type ContactsClientGetResult struct {
	Contact
}

// ContactsClientListResponse contains the response from method ContactsClient.List.
type ContactsClientListResponse struct {
	ContactsClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ContactsClientListResult contains the result from method ContactsClient.List.
type ContactsClientListResult struct {
	ContactListResult
}

// OperationsClientListResponse contains the response from method OperationsClient.List.
type OperationsClientListResponse struct {
	OperationsClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// OperationsClientListResult contains the result from method OperationsClient.List.
type OperationsClientListResult struct {
	OperationListResult
}

// SpacecraftsClientCreateOrUpdatePollerResponse contains the response from method SpacecraftsClient.CreateOrUpdate.
type SpacecraftsClientCreateOrUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *SpacecraftsClientCreateOrUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l SpacecraftsClientCreateOrUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (SpacecraftsClientCreateOrUpdateResponse, error) {
	respType := SpacecraftsClientCreateOrUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.Spacecraft)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a SpacecraftsClientCreateOrUpdatePollerResponse from the provided client and resume token.
func (l *SpacecraftsClientCreateOrUpdatePollerResponse) Resume(ctx context.Context, client *SpacecraftsClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("SpacecraftsClient.CreateOrUpdate", token, client.pl)
	if err != nil {
		return err
	}
	poller := &SpacecraftsClientCreateOrUpdatePoller{
		pt: pt,
	}
	resp, err := poller.Poll(ctx)
	if err != nil {
		return err
	}
	l.Poller = poller
	l.RawResponse = resp
	return nil
}

// SpacecraftsClientCreateOrUpdateResponse contains the response from method SpacecraftsClient.CreateOrUpdate.
type SpacecraftsClientCreateOrUpdateResponse struct {
	SpacecraftsClientCreateOrUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// SpacecraftsClientCreateOrUpdateResult contains the result from method SpacecraftsClient.CreateOrUpdate.
type SpacecraftsClientCreateOrUpdateResult struct {
	Spacecraft
}

// SpacecraftsClientDeletePollerResponse contains the response from method SpacecraftsClient.Delete.
type SpacecraftsClientDeletePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *SpacecraftsClientDeletePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l SpacecraftsClientDeletePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (SpacecraftsClientDeleteResponse, error) {
	respType := SpacecraftsClientDeleteResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a SpacecraftsClientDeletePollerResponse from the provided client and resume token.
func (l *SpacecraftsClientDeletePollerResponse) Resume(ctx context.Context, client *SpacecraftsClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("SpacecraftsClient.Delete", token, client.pl)
	if err != nil {
		return err
	}
	poller := &SpacecraftsClientDeletePoller{
		pt: pt,
	}
	resp, err := poller.Poll(ctx)
	if err != nil {
		return err
	}
	l.Poller = poller
	l.RawResponse = resp
	return nil
}

// SpacecraftsClientDeleteResponse contains the response from method SpacecraftsClient.Delete.
type SpacecraftsClientDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// SpacecraftsClientGetResponse contains the response from method SpacecraftsClient.Get.
type SpacecraftsClientGetResponse struct {
	SpacecraftsClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// SpacecraftsClientGetResult contains the result from method SpacecraftsClient.Get.
type SpacecraftsClientGetResult struct {
	Spacecraft
}

// SpacecraftsClientListAvailableContactsPollerResponse contains the response from method SpacecraftsClient.ListAvailableContacts.
type SpacecraftsClientListAvailableContactsPollerResponse struct {
	// Poller contains an initialized poller.
	Poller *SpacecraftsClientListAvailableContactsPoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l SpacecraftsClientListAvailableContactsPollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (SpacecraftsClientListAvailableContactsResponse, error) {
	respType := SpacecraftsClientListAvailableContactsResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.AvailableContactsListResult)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a SpacecraftsClientListAvailableContactsPollerResponse from the provided client and resume token.
func (l *SpacecraftsClientListAvailableContactsPollerResponse) Resume(ctx context.Context, client *SpacecraftsClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("SpacecraftsClient.ListAvailableContacts", token, client.pl)
	if err != nil {
		return err
	}
	poller := &SpacecraftsClientListAvailableContactsPoller{
		pt: pt,
	}
	resp, err := poller.Poll(ctx)
	if err != nil {
		return err
	}
	l.Poller = poller
	l.RawResponse = resp
	return nil
}

// SpacecraftsClientListAvailableContactsResponse contains the response from method SpacecraftsClient.ListAvailableContacts.
type SpacecraftsClientListAvailableContactsResponse struct {
	SpacecraftsClientListAvailableContactsResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// SpacecraftsClientListAvailableContactsResult contains the result from method SpacecraftsClient.ListAvailableContacts.
type SpacecraftsClientListAvailableContactsResult struct {
	AvailableContactsListResult
}

// SpacecraftsClientListBySubscriptionResponse contains the response from method SpacecraftsClient.ListBySubscription.
type SpacecraftsClientListBySubscriptionResponse struct {
	SpacecraftsClientListBySubscriptionResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// SpacecraftsClientListBySubscriptionResult contains the result from method SpacecraftsClient.ListBySubscription.
type SpacecraftsClientListBySubscriptionResult struct {
	SpacecraftListResult
}

// SpacecraftsClientListResponse contains the response from method SpacecraftsClient.List.
type SpacecraftsClientListResponse struct {
	SpacecraftsClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// SpacecraftsClientListResult contains the result from method SpacecraftsClient.List.
type SpacecraftsClientListResult struct {
	SpacecraftListResult
}

// SpacecraftsClientUpdateTagsResponse contains the response from method SpacecraftsClient.UpdateTags.
type SpacecraftsClientUpdateTagsResponse struct {
	SpacecraftsClientUpdateTagsResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// SpacecraftsClientUpdateTagsResult contains the result from method SpacecraftsClient.UpdateTags.
type SpacecraftsClientUpdateTagsResult struct {
	Spacecraft
}
