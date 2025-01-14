//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armcdn

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"net/url"
	"strings"
)

// AFDOriginsClient contains the methods for the AFDOrigins group.
// Don't use this type directly, use NewAFDOriginsClient() instead.
type AFDOriginsClient struct {
	host           string
	subscriptionID string
	pl             runtime.Pipeline
}

// NewAFDOriginsClient creates a new instance of AFDOriginsClient with the specified values.
// subscriptionID - Azure Subscription ID.
// credential - used to authorize requests. Usually a credential from azidentity.
// options - pass nil to accept the default values.
func NewAFDOriginsClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *AFDOriginsClient {
	if options == nil {
		options = &arm.ClientOptions{}
	}
	ep := options.Endpoint
	if len(ep) == 0 {
		ep = arm.AzurePublicCloud
	}
	client := &AFDOriginsClient{
		subscriptionID: subscriptionID,
		host:           string(ep),
		pl:             armruntime.NewPipeline(moduleName, moduleVersion, credential, runtime.PipelineOptions{}, options),
	}
	return client
}

// BeginCreate - Creates a new origin within the specified origin group.
// If the operation fails it returns an *azcore.ResponseError type.
// resourceGroupName - Name of the Resource group within the Azure subscription.
// profileName - Name of the Azure Front Door Standard or Azure Front Door Premium profile which is unique within the resource
// group.
// originGroupName - Name of the origin group which is unique within the profile.
// originName - Name of the origin that is unique within the profile.
// origin - Origin properties
// options - AFDOriginsClientBeginCreateOptions contains the optional parameters for the AFDOriginsClient.BeginCreate method.
func (client *AFDOriginsClient) BeginCreate(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, origin AFDOrigin, options *AFDOriginsClientBeginCreateOptions) (AFDOriginsClientCreatePollerResponse, error) {
	resp, err := client.create(ctx, resourceGroupName, profileName, originGroupName, originName, origin, options)
	if err != nil {
		return AFDOriginsClientCreatePollerResponse{}, err
	}
	result := AFDOriginsClientCreatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("AFDOriginsClient.Create", "azure-async-operation", resp, client.pl)
	if err != nil {
		return AFDOriginsClientCreatePollerResponse{}, err
	}
	result.Poller = &AFDOriginsClientCreatePoller{
		pt: pt,
	}
	return result, nil
}

// Create - Creates a new origin within the specified origin group.
// If the operation fails it returns an *azcore.ResponseError type.
func (client *AFDOriginsClient) create(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, origin AFDOrigin, options *AFDOriginsClientBeginCreateOptions) (*http.Response, error) {
	req, err := client.createCreateRequest(ctx, resourceGroupName, profileName, originGroupName, originName, origin, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusCreated, http.StatusAccepted) {
		return nil, runtime.NewResponseError(resp)
	}
	return resp, nil
}

// createCreateRequest creates the Create request.
func (client *AFDOriginsClient) createCreateRequest(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, origin AFDOrigin, options *AFDOriginsClientBeginCreateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cdn/profiles/{profileName}/originGroups/{originGroupName}/origins/{originName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if profileName == "" {
		return nil, errors.New("parameter profileName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{profileName}", url.PathEscape(profileName))
	if originGroupName == "" {
		return nil, errors.New("parameter originGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{originGroupName}", url.PathEscape(originGroupName))
	if originName == "" {
		return nil, errors.New("parameter originName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{originName}", url.PathEscape(originName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.host, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, origin)
}

// BeginDelete - Deletes an existing origin within an origin group.
// If the operation fails it returns an *azcore.ResponseError type.
// resourceGroupName - Name of the Resource group within the Azure subscription.
// profileName - Name of the Azure Front Door Standard or Azure Front Door Premium profile which is unique within the resource
// group.
// originGroupName - Name of the origin group which is unique within the profile.
// originName - Name of the origin which is unique within the profile.
// options - AFDOriginsClientBeginDeleteOptions contains the optional parameters for the AFDOriginsClient.BeginDelete method.
func (client *AFDOriginsClient) BeginDelete(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, options *AFDOriginsClientBeginDeleteOptions) (AFDOriginsClientDeletePollerResponse, error) {
	resp, err := client.deleteOperation(ctx, resourceGroupName, profileName, originGroupName, originName, options)
	if err != nil {
		return AFDOriginsClientDeletePollerResponse{}, err
	}
	result := AFDOriginsClientDeletePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("AFDOriginsClient.Delete", "azure-async-operation", resp, client.pl)
	if err != nil {
		return AFDOriginsClientDeletePollerResponse{}, err
	}
	result.Poller = &AFDOriginsClientDeletePoller{
		pt: pt,
	}
	return result, nil
}

// Delete - Deletes an existing origin within an origin group.
// If the operation fails it returns an *azcore.ResponseError type.
func (client *AFDOriginsClient) deleteOperation(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, options *AFDOriginsClientBeginDeleteOptions) (*http.Response, error) {
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, profileName, originGroupName, originName, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusAccepted, http.StatusNoContent) {
		return nil, runtime.NewResponseError(resp)
	}
	return resp, nil
}

// deleteCreateRequest creates the Delete request.
func (client *AFDOriginsClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, options *AFDOriginsClientBeginDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cdn/profiles/{profileName}/originGroups/{originGroupName}/origins/{originName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if profileName == "" {
		return nil, errors.New("parameter profileName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{profileName}", url.PathEscape(profileName))
	if originGroupName == "" {
		return nil, errors.New("parameter originGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{originGroupName}", url.PathEscape(originGroupName))
	if originName == "" {
		return nil, errors.New("parameter originName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{originName}", url.PathEscape(originName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.host, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// Get - Gets an existing origin within an origin group.
// If the operation fails it returns an *azcore.ResponseError type.
// resourceGroupName - Name of the Resource group within the Azure subscription.
// profileName - Name of the Azure Front Door Standard or Azure Front Door Premium profile which is unique within the resource
// group.
// originGroupName - Name of the origin group which is unique within the profile.
// originName - Name of the origin which is unique within the profile.
// options - AFDOriginsClientGetOptions contains the optional parameters for the AFDOriginsClient.Get method.
func (client *AFDOriginsClient) Get(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, options *AFDOriginsClientGetOptions) (AFDOriginsClientGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, profileName, originGroupName, originName, options)
	if err != nil {
		return AFDOriginsClientGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return AFDOriginsClientGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return AFDOriginsClientGetResponse{}, runtime.NewResponseError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *AFDOriginsClient) getCreateRequest(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, options *AFDOriginsClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cdn/profiles/{profileName}/originGroups/{originGroupName}/origins/{originName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if profileName == "" {
		return nil, errors.New("parameter profileName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{profileName}", url.PathEscape(profileName))
	if originGroupName == "" {
		return nil, errors.New("parameter originGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{originGroupName}", url.PathEscape(originGroupName))
	if originName == "" {
		return nil, errors.New("parameter originName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{originName}", url.PathEscape(originName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.host, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *AFDOriginsClient) getHandleResponse(resp *http.Response) (AFDOriginsClientGetResponse, error) {
	result := AFDOriginsClientGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.AFDOrigin); err != nil {
		return AFDOriginsClientGetResponse{}, err
	}
	return result, nil
}

// ListByOriginGroup - Lists all of the existing origins within an origin group.
// If the operation fails it returns an *azcore.ResponseError type.
// resourceGroupName - Name of the Resource group within the Azure subscription.
// profileName - Name of the Azure Front Door Standard or Azure Front Door Premium profile which is unique within the resource
// group.
// originGroupName - Name of the origin group which is unique within the profile.
// options - AFDOriginsClientListByOriginGroupOptions contains the optional parameters for the AFDOriginsClient.ListByOriginGroup
// method.
func (client *AFDOriginsClient) ListByOriginGroup(resourceGroupName string, profileName string, originGroupName string, options *AFDOriginsClientListByOriginGroupOptions) *AFDOriginsClientListByOriginGroupPager {
	return &AFDOriginsClientListByOriginGroupPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listByOriginGroupCreateRequest(ctx, resourceGroupName, profileName, originGroupName, options)
		},
		advancer: func(ctx context.Context, resp AFDOriginsClientListByOriginGroupResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.AFDOriginListResult.NextLink)
		},
	}
}

// listByOriginGroupCreateRequest creates the ListByOriginGroup request.
func (client *AFDOriginsClient) listByOriginGroupCreateRequest(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, options *AFDOriginsClientListByOriginGroupOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cdn/profiles/{profileName}/originGroups/{originGroupName}/origins"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if profileName == "" {
		return nil, errors.New("parameter profileName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{profileName}", url.PathEscape(profileName))
	if originGroupName == "" {
		return nil, errors.New("parameter originGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{originGroupName}", url.PathEscape(originGroupName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.host, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listByOriginGroupHandleResponse handles the ListByOriginGroup response.
func (client *AFDOriginsClient) listByOriginGroupHandleResponse(resp *http.Response) (AFDOriginsClientListByOriginGroupResponse, error) {
	result := AFDOriginsClientListByOriginGroupResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.AFDOriginListResult); err != nil {
		return AFDOriginsClientListByOriginGroupResponse{}, err
	}
	return result, nil
}

// BeginUpdate - Updates an existing origin within an origin group.
// If the operation fails it returns an *azcore.ResponseError type.
// resourceGroupName - Name of the Resource group within the Azure subscription.
// profileName - Name of the Azure Front Door Standard or Azure Front Door Premium profile which is unique within the resource
// group.
// originGroupName - Name of the origin group which is unique within the profile.
// originName - Name of the origin which is unique within the profile.
// originUpdateProperties - Origin properties
// options - AFDOriginsClientBeginUpdateOptions contains the optional parameters for the AFDOriginsClient.BeginUpdate method.
func (client *AFDOriginsClient) BeginUpdate(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, originUpdateProperties AFDOriginUpdateParameters, options *AFDOriginsClientBeginUpdateOptions) (AFDOriginsClientUpdatePollerResponse, error) {
	resp, err := client.update(ctx, resourceGroupName, profileName, originGroupName, originName, originUpdateProperties, options)
	if err != nil {
		return AFDOriginsClientUpdatePollerResponse{}, err
	}
	result := AFDOriginsClientUpdatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("AFDOriginsClient.Update", "azure-async-operation", resp, client.pl)
	if err != nil {
		return AFDOriginsClientUpdatePollerResponse{}, err
	}
	result.Poller = &AFDOriginsClientUpdatePoller{
		pt: pt,
	}
	return result, nil
}

// Update - Updates an existing origin within an origin group.
// If the operation fails it returns an *azcore.ResponseError type.
func (client *AFDOriginsClient) update(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, originUpdateProperties AFDOriginUpdateParameters, options *AFDOriginsClientBeginUpdateOptions) (*http.Response, error) {
	req, err := client.updateCreateRequest(ctx, resourceGroupName, profileName, originGroupName, originName, originUpdateProperties, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusAccepted) {
		return nil, runtime.NewResponseError(resp)
	}
	return resp, nil
}

// updateCreateRequest creates the Update request.
func (client *AFDOriginsClient) updateCreateRequest(ctx context.Context, resourceGroupName string, profileName string, originGroupName string, originName string, originUpdateProperties AFDOriginUpdateParameters, options *AFDOriginsClientBeginUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Cdn/profiles/{profileName}/originGroups/{originGroupName}/origins/{originName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if profileName == "" {
		return nil, errors.New("parameter profileName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{profileName}", url.PathEscape(profileName))
	if originGroupName == "" {
		return nil, errors.New("parameter originGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{originGroupName}", url.PathEscape(originGroupName))
	if originName == "" {
		return nil, errors.New("parameter originName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{originName}", url.PathEscape(originName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodPatch, runtime.JoinPaths(client.host, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, originUpdateProperties)
}
