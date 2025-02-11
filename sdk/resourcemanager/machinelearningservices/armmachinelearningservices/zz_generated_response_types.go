//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armmachinelearningservices

import (
	"context"
	armruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"net/http"
	"time"
)

// ComputeClientCreateOrUpdatePollerResponse contains the response from method ComputeClient.CreateOrUpdate.
type ComputeClientCreateOrUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ComputeClientCreateOrUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ComputeClientCreateOrUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ComputeClientCreateOrUpdateResponse, error) {
	respType := ComputeClientCreateOrUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.ComputeResource)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ComputeClientCreateOrUpdatePollerResponse from the provided client and resume token.
func (l *ComputeClientCreateOrUpdatePollerResponse) Resume(ctx context.Context, client *ComputeClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ComputeClient.CreateOrUpdate", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ComputeClientCreateOrUpdatePoller{
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

// ComputeClientCreateOrUpdateResponse contains the response from method ComputeClient.CreateOrUpdate.
type ComputeClientCreateOrUpdateResponse struct {
	ComputeClientCreateOrUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ComputeClientCreateOrUpdateResult contains the result from method ComputeClient.CreateOrUpdate.
type ComputeClientCreateOrUpdateResult struct {
	ComputeResource
}

// ComputeClientDeletePollerResponse contains the response from method ComputeClient.Delete.
type ComputeClientDeletePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ComputeClientDeletePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ComputeClientDeletePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ComputeClientDeleteResponse, error) {
	respType := ComputeClientDeleteResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ComputeClientDeletePollerResponse from the provided client and resume token.
func (l *ComputeClientDeletePollerResponse) Resume(ctx context.Context, client *ComputeClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ComputeClient.Delete", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ComputeClientDeletePoller{
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

// ComputeClientDeleteResponse contains the response from method ComputeClient.Delete.
type ComputeClientDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ComputeClientGetResponse contains the response from method ComputeClient.Get.
type ComputeClientGetResponse struct {
	ComputeClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ComputeClientGetResult contains the result from method ComputeClient.Get.
type ComputeClientGetResult struct {
	ComputeResource
}

// ComputeClientListKeysResponse contains the response from method ComputeClient.ListKeys.
type ComputeClientListKeysResponse struct {
	ComputeClientListKeysResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ComputeClientListKeysResult contains the result from method ComputeClient.ListKeys.
type ComputeClientListKeysResult struct {
	ComputeSecretsClassification
}

// UnmarshalJSON implements the json.Unmarshaller interface for type ComputeClientListKeysResult.
func (c *ComputeClientListKeysResult) UnmarshalJSON(data []byte) error {
	res, err := unmarshalComputeSecretsClassification(data)
	if err != nil {
		return err
	}
	c.ComputeSecretsClassification = res
	return nil
}

// ComputeClientListNodesResponse contains the response from method ComputeClient.ListNodes.
type ComputeClientListNodesResponse struct {
	ComputeClientListNodesResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ComputeClientListNodesResult contains the result from method ComputeClient.ListNodes.
type ComputeClientListNodesResult struct {
	AmlComputeNodesInformation
}

// ComputeClientListResponse contains the response from method ComputeClient.List.
type ComputeClientListResponse struct {
	ComputeClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ComputeClientListResult contains the result from method ComputeClient.List.
type ComputeClientListResult struct {
	PaginatedComputeResourcesList
}

// ComputeClientRestartPollerResponse contains the response from method ComputeClient.Restart.
type ComputeClientRestartPollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ComputeClientRestartPoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ComputeClientRestartPollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ComputeClientRestartResponse, error) {
	respType := ComputeClientRestartResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ComputeClientRestartPollerResponse from the provided client and resume token.
func (l *ComputeClientRestartPollerResponse) Resume(ctx context.Context, client *ComputeClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ComputeClient.Restart", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ComputeClientRestartPoller{
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

// ComputeClientRestartResponse contains the response from method ComputeClient.Restart.
type ComputeClientRestartResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ComputeClientStartPollerResponse contains the response from method ComputeClient.Start.
type ComputeClientStartPollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ComputeClientStartPoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ComputeClientStartPollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ComputeClientStartResponse, error) {
	respType := ComputeClientStartResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ComputeClientStartPollerResponse from the provided client and resume token.
func (l *ComputeClientStartPollerResponse) Resume(ctx context.Context, client *ComputeClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ComputeClient.Start", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ComputeClientStartPoller{
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

// ComputeClientStartResponse contains the response from method ComputeClient.Start.
type ComputeClientStartResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ComputeClientStopPollerResponse contains the response from method ComputeClient.Stop.
type ComputeClientStopPollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ComputeClientStopPoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ComputeClientStopPollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ComputeClientStopResponse, error) {
	respType := ComputeClientStopResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ComputeClientStopPollerResponse from the provided client and resume token.
func (l *ComputeClientStopPollerResponse) Resume(ctx context.Context, client *ComputeClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ComputeClient.Stop", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ComputeClientStopPoller{
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

// ComputeClientStopResponse contains the response from method ComputeClient.Stop.
type ComputeClientStopResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ComputeClientUpdatePollerResponse contains the response from method ComputeClient.Update.
type ComputeClientUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ComputeClientUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ComputeClientUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ComputeClientUpdateResponse, error) {
	respType := ComputeClientUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.ComputeResource)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ComputeClientUpdatePollerResponse from the provided client and resume token.
func (l *ComputeClientUpdatePollerResponse) Resume(ctx context.Context, client *ComputeClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ComputeClient.Update", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ComputeClientUpdatePoller{
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

// ComputeClientUpdateResponse contains the response from method ComputeClient.Update.
type ComputeClientUpdateResponse struct {
	ComputeClientUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ComputeClientUpdateResult contains the result from method ComputeClient.Update.
type ComputeClientUpdateResult struct {
	ComputeResource
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

// PrivateEndpointConnectionsClientCreateOrUpdateResponse contains the response from method PrivateEndpointConnectionsClient.CreateOrUpdate.
type PrivateEndpointConnectionsClientCreateOrUpdateResponse struct {
	PrivateEndpointConnectionsClientCreateOrUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PrivateEndpointConnectionsClientCreateOrUpdateResult contains the result from method PrivateEndpointConnectionsClient.CreateOrUpdate.
type PrivateEndpointConnectionsClientCreateOrUpdateResult struct {
	PrivateEndpointConnection
}

// PrivateEndpointConnectionsClientDeleteResponse contains the response from method PrivateEndpointConnectionsClient.Delete.
type PrivateEndpointConnectionsClientDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PrivateEndpointConnectionsClientGetResponse contains the response from method PrivateEndpointConnectionsClient.Get.
type PrivateEndpointConnectionsClientGetResponse struct {
	PrivateEndpointConnectionsClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PrivateEndpointConnectionsClientGetResult contains the result from method PrivateEndpointConnectionsClient.Get.
type PrivateEndpointConnectionsClientGetResult struct {
	PrivateEndpointConnection
}

// PrivateEndpointConnectionsClientListResponse contains the response from method PrivateEndpointConnectionsClient.List.
type PrivateEndpointConnectionsClientListResponse struct {
	PrivateEndpointConnectionsClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PrivateEndpointConnectionsClientListResult contains the result from method PrivateEndpointConnectionsClient.List.
type PrivateEndpointConnectionsClientListResult struct {
	PrivateEndpointConnectionListResult
}

// PrivateLinkResourcesClientListResponse contains the response from method PrivateLinkResourcesClient.List.
type PrivateLinkResourcesClientListResponse struct {
	PrivateLinkResourcesClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PrivateLinkResourcesClientListResult contains the result from method PrivateLinkResourcesClient.List.
type PrivateLinkResourcesClientListResult struct {
	PrivateLinkResourceListResult
}

// QuotasClientListResponse contains the response from method QuotasClient.List.
type QuotasClientListResponse struct {
	QuotasClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// QuotasClientListResult contains the result from method QuotasClient.List.
type QuotasClientListResult struct {
	ListWorkspaceQuotas
}

// QuotasClientUpdateResponse contains the response from method QuotasClient.Update.
type QuotasClientUpdateResponse struct {
	QuotasClientUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// QuotasClientUpdateResult contains the result from method QuotasClient.Update.
type QuotasClientUpdateResult struct {
	UpdateWorkspaceQuotasResult
}

// UsagesClientListResponse contains the response from method UsagesClient.List.
type UsagesClientListResponse struct {
	UsagesClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// UsagesClientListResult contains the result from method UsagesClient.List.
type UsagesClientListResult struct {
	ListUsagesResult
}

// VirtualMachineSizesClientListResponse contains the response from method VirtualMachineSizesClient.List.
type VirtualMachineSizesClientListResponse struct {
	VirtualMachineSizesClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// VirtualMachineSizesClientListResult contains the result from method VirtualMachineSizesClient.List.
type VirtualMachineSizesClientListResult struct {
	VirtualMachineSizeListResult
}

// WorkspaceConnectionsClientCreateResponse contains the response from method WorkspaceConnectionsClient.Create.
type WorkspaceConnectionsClientCreateResponse struct {
	WorkspaceConnectionsClientCreateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspaceConnectionsClientCreateResult contains the result from method WorkspaceConnectionsClient.Create.
type WorkspaceConnectionsClientCreateResult struct {
	WorkspaceConnection
}

// WorkspaceConnectionsClientDeleteResponse contains the response from method WorkspaceConnectionsClient.Delete.
type WorkspaceConnectionsClientDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspaceConnectionsClientGetResponse contains the response from method WorkspaceConnectionsClient.Get.
type WorkspaceConnectionsClientGetResponse struct {
	WorkspaceConnectionsClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspaceConnectionsClientGetResult contains the result from method WorkspaceConnectionsClient.Get.
type WorkspaceConnectionsClientGetResult struct {
	WorkspaceConnection
}

// WorkspaceConnectionsClientListResponse contains the response from method WorkspaceConnectionsClient.List.
type WorkspaceConnectionsClientListResponse struct {
	WorkspaceConnectionsClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspaceConnectionsClientListResult contains the result from method WorkspaceConnectionsClient.List.
type WorkspaceConnectionsClientListResult struct {
	PaginatedWorkspaceConnectionsList
}

// WorkspaceFeaturesClientListResponse contains the response from method WorkspaceFeaturesClient.List.
type WorkspaceFeaturesClientListResponse struct {
	WorkspaceFeaturesClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspaceFeaturesClientListResult contains the result from method WorkspaceFeaturesClient.List.
type WorkspaceFeaturesClientListResult struct {
	ListAmlUserFeatureResult
}

// WorkspaceSKUsClientListResponse contains the response from method WorkspaceSKUsClient.List.
type WorkspaceSKUsClientListResponse struct {
	WorkspaceSKUsClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspaceSKUsClientListResult contains the result from method WorkspaceSKUsClient.List.
type WorkspaceSKUsClientListResult struct {
	SKUListResult
}

// WorkspacesClientCreateOrUpdatePollerResponse contains the response from method WorkspacesClient.CreateOrUpdate.
type WorkspacesClientCreateOrUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *WorkspacesClientCreateOrUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l WorkspacesClientCreateOrUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (WorkspacesClientCreateOrUpdateResponse, error) {
	respType := WorkspacesClientCreateOrUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.Workspace)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a WorkspacesClientCreateOrUpdatePollerResponse from the provided client and resume token.
func (l *WorkspacesClientCreateOrUpdatePollerResponse) Resume(ctx context.Context, client *WorkspacesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("WorkspacesClient.CreateOrUpdate", token, client.pl)
	if err != nil {
		return err
	}
	poller := &WorkspacesClientCreateOrUpdatePoller{
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

// WorkspacesClientCreateOrUpdateResponse contains the response from method WorkspacesClient.CreateOrUpdate.
type WorkspacesClientCreateOrUpdateResponse struct {
	WorkspacesClientCreateOrUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientCreateOrUpdateResult contains the result from method WorkspacesClient.CreateOrUpdate.
type WorkspacesClientCreateOrUpdateResult struct {
	Workspace
}

// WorkspacesClientDeletePollerResponse contains the response from method WorkspacesClient.Delete.
type WorkspacesClientDeletePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *WorkspacesClientDeletePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l WorkspacesClientDeletePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (WorkspacesClientDeleteResponse, error) {
	respType := WorkspacesClientDeleteResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a WorkspacesClientDeletePollerResponse from the provided client and resume token.
func (l *WorkspacesClientDeletePollerResponse) Resume(ctx context.Context, client *WorkspacesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("WorkspacesClient.Delete", token, client.pl)
	if err != nil {
		return err
	}
	poller := &WorkspacesClientDeletePoller{
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

// WorkspacesClientDeleteResponse contains the response from method WorkspacesClient.Delete.
type WorkspacesClientDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientDiagnosePollerResponse contains the response from method WorkspacesClient.Diagnose.
type WorkspacesClientDiagnosePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *WorkspacesClientDiagnosePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l WorkspacesClientDiagnosePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (WorkspacesClientDiagnoseResponse, error) {
	respType := WorkspacesClientDiagnoseResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.DiagnoseResponseResult)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a WorkspacesClientDiagnosePollerResponse from the provided client and resume token.
func (l *WorkspacesClientDiagnosePollerResponse) Resume(ctx context.Context, client *WorkspacesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("WorkspacesClient.Diagnose", token, client.pl)
	if err != nil {
		return err
	}
	poller := &WorkspacesClientDiagnosePoller{
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

// WorkspacesClientDiagnoseResponse contains the response from method WorkspacesClient.Diagnose.
type WorkspacesClientDiagnoseResponse struct {
	WorkspacesClientDiagnoseResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientDiagnoseResult contains the result from method WorkspacesClient.Diagnose.
type WorkspacesClientDiagnoseResult struct {
	DiagnoseResponseResult
}

// WorkspacesClientGetResponse contains the response from method WorkspacesClient.Get.
type WorkspacesClientGetResponse struct {
	WorkspacesClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientGetResult contains the result from method WorkspacesClient.Get.
type WorkspacesClientGetResult struct {
	Workspace
}

// WorkspacesClientListByResourceGroupResponse contains the response from method WorkspacesClient.ListByResourceGroup.
type WorkspacesClientListByResourceGroupResponse struct {
	WorkspacesClientListByResourceGroupResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientListByResourceGroupResult contains the result from method WorkspacesClient.ListByResourceGroup.
type WorkspacesClientListByResourceGroupResult struct {
	WorkspaceListResult
}

// WorkspacesClientListBySubscriptionResponse contains the response from method WorkspacesClient.ListBySubscription.
type WorkspacesClientListBySubscriptionResponse struct {
	WorkspacesClientListBySubscriptionResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientListBySubscriptionResult contains the result from method WorkspacesClient.ListBySubscription.
type WorkspacesClientListBySubscriptionResult struct {
	WorkspaceListResult
}

// WorkspacesClientListKeysResponse contains the response from method WorkspacesClient.ListKeys.
type WorkspacesClientListKeysResponse struct {
	WorkspacesClientListKeysResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientListKeysResult contains the result from method WorkspacesClient.ListKeys.
type WorkspacesClientListKeysResult struct {
	ListWorkspaceKeysResult
}

// WorkspacesClientListNotebookAccessTokenResponse contains the response from method WorkspacesClient.ListNotebookAccessToken.
type WorkspacesClientListNotebookAccessTokenResponse struct {
	WorkspacesClientListNotebookAccessTokenResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientListNotebookAccessTokenResult contains the result from method WorkspacesClient.ListNotebookAccessToken.
type WorkspacesClientListNotebookAccessTokenResult struct {
	NotebookAccessTokenResult
}

// WorkspacesClientListNotebookKeysResponse contains the response from method WorkspacesClient.ListNotebookKeys.
type WorkspacesClientListNotebookKeysResponse struct {
	WorkspacesClientListNotebookKeysResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientListNotebookKeysResult contains the result from method WorkspacesClient.ListNotebookKeys.
type WorkspacesClientListNotebookKeysResult struct {
	ListNotebookKeysResult
}

// WorkspacesClientListOutboundNetworkDependenciesEndpointsResponse contains the response from method WorkspacesClient.ListOutboundNetworkDependenciesEndpoints.
type WorkspacesClientListOutboundNetworkDependenciesEndpointsResponse struct {
	WorkspacesClientListOutboundNetworkDependenciesEndpointsResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientListOutboundNetworkDependenciesEndpointsResult contains the result from method WorkspacesClient.ListOutboundNetworkDependenciesEndpoints.
type WorkspacesClientListOutboundNetworkDependenciesEndpointsResult struct {
	ExternalFQDNResponse
}

// WorkspacesClientListStorageAccountKeysResponse contains the response from method WorkspacesClient.ListStorageAccountKeys.
type WorkspacesClientListStorageAccountKeysResponse struct {
	WorkspacesClientListStorageAccountKeysResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientListStorageAccountKeysResult contains the result from method WorkspacesClient.ListStorageAccountKeys.
type WorkspacesClientListStorageAccountKeysResult struct {
	ListStorageAccountKeysResult
}

// WorkspacesClientPrepareNotebookPollerResponse contains the response from method WorkspacesClient.PrepareNotebook.
type WorkspacesClientPrepareNotebookPollerResponse struct {
	// Poller contains an initialized poller.
	Poller *WorkspacesClientPrepareNotebookPoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l WorkspacesClientPrepareNotebookPollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (WorkspacesClientPrepareNotebookResponse, error) {
	respType := WorkspacesClientPrepareNotebookResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.NotebookResourceInfo)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a WorkspacesClientPrepareNotebookPollerResponse from the provided client and resume token.
func (l *WorkspacesClientPrepareNotebookPollerResponse) Resume(ctx context.Context, client *WorkspacesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("WorkspacesClient.PrepareNotebook", token, client.pl)
	if err != nil {
		return err
	}
	poller := &WorkspacesClientPrepareNotebookPoller{
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

// WorkspacesClientPrepareNotebookResponse contains the response from method WorkspacesClient.PrepareNotebook.
type WorkspacesClientPrepareNotebookResponse struct {
	WorkspacesClientPrepareNotebookResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientPrepareNotebookResult contains the result from method WorkspacesClient.PrepareNotebook.
type WorkspacesClientPrepareNotebookResult struct {
	NotebookResourceInfo
}

// WorkspacesClientResyncKeysPollerResponse contains the response from method WorkspacesClient.ResyncKeys.
type WorkspacesClientResyncKeysPollerResponse struct {
	// Poller contains an initialized poller.
	Poller *WorkspacesClientResyncKeysPoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l WorkspacesClientResyncKeysPollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (WorkspacesClientResyncKeysResponse, error) {
	respType := WorkspacesClientResyncKeysResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a WorkspacesClientResyncKeysPollerResponse from the provided client and resume token.
func (l *WorkspacesClientResyncKeysPollerResponse) Resume(ctx context.Context, client *WorkspacesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("WorkspacesClient.ResyncKeys", token, client.pl)
	if err != nil {
		return err
	}
	poller := &WorkspacesClientResyncKeysPoller{
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

// WorkspacesClientResyncKeysResponse contains the response from method WorkspacesClient.ResyncKeys.
type WorkspacesClientResyncKeysResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientUpdateResponse contains the response from method WorkspacesClient.Update.
type WorkspacesClientUpdateResponse struct {
	WorkspacesClientUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesClientUpdateResult contains the result from method WorkspacesClient.Update.
type WorkspacesClientUpdateResult struct {
	Workspace
}
