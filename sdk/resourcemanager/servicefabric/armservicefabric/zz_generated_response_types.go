//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armservicefabric

import (
	"context"
	armruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"net/http"
	"time"
)

// ApplicationTypeVersionsClientCreateOrUpdatePollerResponse contains the response from method ApplicationTypeVersionsClient.CreateOrUpdate.
type ApplicationTypeVersionsClientCreateOrUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ApplicationTypeVersionsClientCreateOrUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ApplicationTypeVersionsClientCreateOrUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ApplicationTypeVersionsClientCreateOrUpdateResponse, error) {
	respType := ApplicationTypeVersionsClientCreateOrUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.ApplicationTypeVersionResource)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ApplicationTypeVersionsClientCreateOrUpdatePollerResponse from the provided client and resume token.
func (l *ApplicationTypeVersionsClientCreateOrUpdatePollerResponse) Resume(ctx context.Context, client *ApplicationTypeVersionsClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ApplicationTypeVersionsClient.CreateOrUpdate", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ApplicationTypeVersionsClientCreateOrUpdatePoller{
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

// ApplicationTypeVersionsClientCreateOrUpdateResponse contains the response from method ApplicationTypeVersionsClient.CreateOrUpdate.
type ApplicationTypeVersionsClientCreateOrUpdateResponse struct {
	ApplicationTypeVersionsClientCreateOrUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ApplicationTypeVersionsClientCreateOrUpdateResult contains the result from method ApplicationTypeVersionsClient.CreateOrUpdate.
type ApplicationTypeVersionsClientCreateOrUpdateResult struct {
	ApplicationTypeVersionResource
}

// ApplicationTypeVersionsClientDeletePollerResponse contains the response from method ApplicationTypeVersionsClient.Delete.
type ApplicationTypeVersionsClientDeletePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ApplicationTypeVersionsClientDeletePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ApplicationTypeVersionsClientDeletePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ApplicationTypeVersionsClientDeleteResponse, error) {
	respType := ApplicationTypeVersionsClientDeleteResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ApplicationTypeVersionsClientDeletePollerResponse from the provided client and resume token.
func (l *ApplicationTypeVersionsClientDeletePollerResponse) Resume(ctx context.Context, client *ApplicationTypeVersionsClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ApplicationTypeVersionsClient.Delete", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ApplicationTypeVersionsClientDeletePoller{
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

// ApplicationTypeVersionsClientDeleteResponse contains the response from method ApplicationTypeVersionsClient.Delete.
type ApplicationTypeVersionsClientDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ApplicationTypeVersionsClientGetResponse contains the response from method ApplicationTypeVersionsClient.Get.
type ApplicationTypeVersionsClientGetResponse struct {
	ApplicationTypeVersionsClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ApplicationTypeVersionsClientGetResult contains the result from method ApplicationTypeVersionsClient.Get.
type ApplicationTypeVersionsClientGetResult struct {
	ApplicationTypeVersionResource
}

// ApplicationTypeVersionsClientListResponse contains the response from method ApplicationTypeVersionsClient.List.
type ApplicationTypeVersionsClientListResponse struct {
	ApplicationTypeVersionsClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ApplicationTypeVersionsClientListResult contains the result from method ApplicationTypeVersionsClient.List.
type ApplicationTypeVersionsClientListResult struct {
	ApplicationTypeVersionResourceList
}

// ApplicationTypesClientCreateOrUpdateResponse contains the response from method ApplicationTypesClient.CreateOrUpdate.
type ApplicationTypesClientCreateOrUpdateResponse struct {
	ApplicationTypesClientCreateOrUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ApplicationTypesClientCreateOrUpdateResult contains the result from method ApplicationTypesClient.CreateOrUpdate.
type ApplicationTypesClientCreateOrUpdateResult struct {
	ApplicationTypeResource
}

// ApplicationTypesClientDeletePollerResponse contains the response from method ApplicationTypesClient.Delete.
type ApplicationTypesClientDeletePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ApplicationTypesClientDeletePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ApplicationTypesClientDeletePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ApplicationTypesClientDeleteResponse, error) {
	respType := ApplicationTypesClientDeleteResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ApplicationTypesClientDeletePollerResponse from the provided client and resume token.
func (l *ApplicationTypesClientDeletePollerResponse) Resume(ctx context.Context, client *ApplicationTypesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ApplicationTypesClient.Delete", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ApplicationTypesClientDeletePoller{
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

// ApplicationTypesClientDeleteResponse contains the response from method ApplicationTypesClient.Delete.
type ApplicationTypesClientDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ApplicationTypesClientGetResponse contains the response from method ApplicationTypesClient.Get.
type ApplicationTypesClientGetResponse struct {
	ApplicationTypesClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ApplicationTypesClientGetResult contains the result from method ApplicationTypesClient.Get.
type ApplicationTypesClientGetResult struct {
	ApplicationTypeResource
}

// ApplicationTypesClientListResponse contains the response from method ApplicationTypesClient.List.
type ApplicationTypesClientListResponse struct {
	ApplicationTypesClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ApplicationTypesClientListResult contains the result from method ApplicationTypesClient.List.
type ApplicationTypesClientListResult struct {
	ApplicationTypeResourceList
}

// ApplicationsClientCreateOrUpdatePollerResponse contains the response from method ApplicationsClient.CreateOrUpdate.
type ApplicationsClientCreateOrUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ApplicationsClientCreateOrUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ApplicationsClientCreateOrUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ApplicationsClientCreateOrUpdateResponse, error) {
	respType := ApplicationsClientCreateOrUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.ApplicationResource)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ApplicationsClientCreateOrUpdatePollerResponse from the provided client and resume token.
func (l *ApplicationsClientCreateOrUpdatePollerResponse) Resume(ctx context.Context, client *ApplicationsClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ApplicationsClient.CreateOrUpdate", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ApplicationsClientCreateOrUpdatePoller{
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

// ApplicationsClientCreateOrUpdateResponse contains the response from method ApplicationsClient.CreateOrUpdate.
type ApplicationsClientCreateOrUpdateResponse struct {
	ApplicationsClientCreateOrUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ApplicationsClientCreateOrUpdateResult contains the result from method ApplicationsClient.CreateOrUpdate.
type ApplicationsClientCreateOrUpdateResult struct {
	ApplicationResource
}

// ApplicationsClientDeletePollerResponse contains the response from method ApplicationsClient.Delete.
type ApplicationsClientDeletePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ApplicationsClientDeletePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ApplicationsClientDeletePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ApplicationsClientDeleteResponse, error) {
	respType := ApplicationsClientDeleteResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ApplicationsClientDeletePollerResponse from the provided client and resume token.
func (l *ApplicationsClientDeletePollerResponse) Resume(ctx context.Context, client *ApplicationsClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ApplicationsClient.Delete", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ApplicationsClientDeletePoller{
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

// ApplicationsClientDeleteResponse contains the response from method ApplicationsClient.Delete.
type ApplicationsClientDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ApplicationsClientGetResponse contains the response from method ApplicationsClient.Get.
type ApplicationsClientGetResponse struct {
	ApplicationsClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ApplicationsClientGetResult contains the result from method ApplicationsClient.Get.
type ApplicationsClientGetResult struct {
	ApplicationResource
}

// ApplicationsClientListResponse contains the response from method ApplicationsClient.List.
type ApplicationsClientListResponse struct {
	ApplicationsClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ApplicationsClientListResult contains the result from method ApplicationsClient.List.
type ApplicationsClientListResult struct {
	ApplicationResourceList
}

// ApplicationsClientUpdatePollerResponse contains the response from method ApplicationsClient.Update.
type ApplicationsClientUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ApplicationsClientUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ApplicationsClientUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ApplicationsClientUpdateResponse, error) {
	respType := ApplicationsClientUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.ApplicationResource)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ApplicationsClientUpdatePollerResponse from the provided client and resume token.
func (l *ApplicationsClientUpdatePollerResponse) Resume(ctx context.Context, client *ApplicationsClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ApplicationsClient.Update", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ApplicationsClientUpdatePoller{
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

// ApplicationsClientUpdateResponse contains the response from method ApplicationsClient.Update.
type ApplicationsClientUpdateResponse struct {
	ApplicationsClientUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ApplicationsClientUpdateResult contains the result from method ApplicationsClient.Update.
type ApplicationsClientUpdateResult struct {
	ApplicationResource
}

// ClusterVersionsClientGetByEnvironmentResponse contains the response from method ClusterVersionsClient.GetByEnvironment.
type ClusterVersionsClientGetByEnvironmentResponse struct {
	ClusterVersionsClientGetByEnvironmentResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ClusterVersionsClientGetByEnvironmentResult contains the result from method ClusterVersionsClient.GetByEnvironment.
type ClusterVersionsClientGetByEnvironmentResult struct {
	ClusterCodeVersionsListResult
}

// ClusterVersionsClientGetResponse contains the response from method ClusterVersionsClient.Get.
type ClusterVersionsClientGetResponse struct {
	ClusterVersionsClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ClusterVersionsClientGetResult contains the result from method ClusterVersionsClient.Get.
type ClusterVersionsClientGetResult struct {
	ClusterCodeVersionsListResult
}

// ClusterVersionsClientListByEnvironmentResponse contains the response from method ClusterVersionsClient.ListByEnvironment.
type ClusterVersionsClientListByEnvironmentResponse struct {
	ClusterVersionsClientListByEnvironmentResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ClusterVersionsClientListByEnvironmentResult contains the result from method ClusterVersionsClient.ListByEnvironment.
type ClusterVersionsClientListByEnvironmentResult struct {
	ClusterCodeVersionsListResult
}

// ClusterVersionsClientListResponse contains the response from method ClusterVersionsClient.List.
type ClusterVersionsClientListResponse struct {
	ClusterVersionsClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ClusterVersionsClientListResult contains the result from method ClusterVersionsClient.List.
type ClusterVersionsClientListResult struct {
	ClusterCodeVersionsListResult
}

// ClustersClientCreateOrUpdatePollerResponse contains the response from method ClustersClient.CreateOrUpdate.
type ClustersClientCreateOrUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ClustersClientCreateOrUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ClustersClientCreateOrUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ClustersClientCreateOrUpdateResponse, error) {
	respType := ClustersClientCreateOrUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.Cluster)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ClustersClientCreateOrUpdatePollerResponse from the provided client and resume token.
func (l *ClustersClientCreateOrUpdatePollerResponse) Resume(ctx context.Context, client *ClustersClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ClustersClient.CreateOrUpdate", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ClustersClientCreateOrUpdatePoller{
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

// ClustersClientCreateOrUpdateResponse contains the response from method ClustersClient.CreateOrUpdate.
type ClustersClientCreateOrUpdateResponse struct {
	ClustersClientCreateOrUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ClustersClientCreateOrUpdateResult contains the result from method ClustersClient.CreateOrUpdate.
type ClustersClientCreateOrUpdateResult struct {
	Cluster
}

// ClustersClientDeleteResponse contains the response from method ClustersClient.Delete.
type ClustersClientDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ClustersClientGetResponse contains the response from method ClustersClient.Get.
type ClustersClientGetResponse struct {
	ClustersClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ClustersClientGetResult contains the result from method ClustersClient.Get.
type ClustersClientGetResult struct {
	Cluster
}

// ClustersClientListByResourceGroupResponse contains the response from method ClustersClient.ListByResourceGroup.
type ClustersClientListByResourceGroupResponse struct {
	ClustersClientListByResourceGroupResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ClustersClientListByResourceGroupResult contains the result from method ClustersClient.ListByResourceGroup.
type ClustersClientListByResourceGroupResult struct {
	ClusterListResult
}

// ClustersClientListResponse contains the response from method ClustersClient.List.
type ClustersClientListResponse struct {
	ClustersClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ClustersClientListResult contains the result from method ClustersClient.List.
type ClustersClientListResult struct {
	ClusterListResult
}

// ClustersClientListUpgradableVersionsResponse contains the response from method ClustersClient.ListUpgradableVersions.
type ClustersClientListUpgradableVersionsResponse struct {
	ClustersClientListUpgradableVersionsResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ClustersClientListUpgradableVersionsResult contains the result from method ClustersClient.ListUpgradableVersions.
type ClustersClientListUpgradableVersionsResult struct {
	UpgradableVersionPathResult
}

// ClustersClientUpdatePollerResponse contains the response from method ClustersClient.Update.
type ClustersClientUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ClustersClientUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ClustersClientUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ClustersClientUpdateResponse, error) {
	respType := ClustersClientUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.Cluster)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ClustersClientUpdatePollerResponse from the provided client and resume token.
func (l *ClustersClientUpdatePollerResponse) Resume(ctx context.Context, client *ClustersClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ClustersClient.Update", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ClustersClientUpdatePoller{
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

// ClustersClientUpdateResponse contains the response from method ClustersClient.Update.
type ClustersClientUpdateResponse struct {
	ClustersClientUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ClustersClientUpdateResult contains the result from method ClustersClient.Update.
type ClustersClientUpdateResult struct {
	Cluster
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

// ServicesClientCreateOrUpdatePollerResponse contains the response from method ServicesClient.CreateOrUpdate.
type ServicesClientCreateOrUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ServicesClientCreateOrUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ServicesClientCreateOrUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ServicesClientCreateOrUpdateResponse, error) {
	respType := ServicesClientCreateOrUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.ServiceResource)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ServicesClientCreateOrUpdatePollerResponse from the provided client and resume token.
func (l *ServicesClientCreateOrUpdatePollerResponse) Resume(ctx context.Context, client *ServicesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ServicesClient.CreateOrUpdate", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ServicesClientCreateOrUpdatePoller{
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

// ServicesClientCreateOrUpdateResponse contains the response from method ServicesClient.CreateOrUpdate.
type ServicesClientCreateOrUpdateResponse struct {
	ServicesClientCreateOrUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ServicesClientCreateOrUpdateResult contains the result from method ServicesClient.CreateOrUpdate.
type ServicesClientCreateOrUpdateResult struct {
	ServiceResource
}

// ServicesClientDeletePollerResponse contains the response from method ServicesClient.Delete.
type ServicesClientDeletePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ServicesClientDeletePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ServicesClientDeletePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ServicesClientDeleteResponse, error) {
	respType := ServicesClientDeleteResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ServicesClientDeletePollerResponse from the provided client and resume token.
func (l *ServicesClientDeletePollerResponse) Resume(ctx context.Context, client *ServicesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ServicesClient.Delete", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ServicesClientDeletePoller{
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

// ServicesClientDeleteResponse contains the response from method ServicesClient.Delete.
type ServicesClientDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ServicesClientGetResponse contains the response from method ServicesClient.Get.
type ServicesClientGetResponse struct {
	ServicesClientGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ServicesClientGetResult contains the result from method ServicesClient.Get.
type ServicesClientGetResult struct {
	ServiceResource
}

// ServicesClientListResponse contains the response from method ServicesClient.List.
type ServicesClientListResponse struct {
	ServicesClientListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ServicesClientListResult contains the result from method ServicesClient.List.
type ServicesClientListResult struct {
	ServiceResourceList
}

// ServicesClientUpdatePollerResponse contains the response from method ServicesClient.Update.
type ServicesClientUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *ServicesClientUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l ServicesClientUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (ServicesClientUpdateResponse, error) {
	respType := ServicesClientUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.ServiceResource)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a ServicesClientUpdatePollerResponse from the provided client and resume token.
func (l *ServicesClientUpdatePollerResponse) Resume(ctx context.Context, client *ServicesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("ServicesClient.Update", token, client.pl)
	if err != nil {
		return err
	}
	poller := &ServicesClientUpdatePoller{
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

// ServicesClientUpdateResponse contains the response from method ServicesClient.Update.
type ServicesClientUpdateResponse struct {
	ServicesClientUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// ServicesClientUpdateResult contains the result from method ServicesClient.Update.
type ServicesClientUpdateResult struct {
	ServiceResource
}
