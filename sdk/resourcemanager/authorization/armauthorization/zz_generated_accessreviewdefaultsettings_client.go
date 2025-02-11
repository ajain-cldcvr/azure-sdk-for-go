//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armauthorization

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

// AccessReviewDefaultSettingsClient contains the methods for the AccessReviewDefaultSettings group.
// Don't use this type directly, use NewAccessReviewDefaultSettingsClient() instead.
type AccessReviewDefaultSettingsClient struct {
	host           string
	subscriptionID string
	pl             runtime.Pipeline
}

// NewAccessReviewDefaultSettingsClient creates a new instance of AccessReviewDefaultSettingsClient with the specified values.
// subscriptionID - The ID of the target subscription.
// credential - used to authorize requests. Usually a credential from azidentity.
// options - pass nil to accept the default values.
func NewAccessReviewDefaultSettingsClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *AccessReviewDefaultSettingsClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Endpoint) == 0 {
		cp.Endpoint = arm.AzurePublicCloud
	}
	client := &AccessReviewDefaultSettingsClient{
		subscriptionID: subscriptionID,
		host:           string(cp.Endpoint),
		pl:             armruntime.NewPipeline(moduleName, moduleVersion, credential, runtime.PipelineOptions{}, &cp),
	}
	return client
}

// Get - Get access review default settings for the subscription
// If the operation fails it returns an *azcore.ResponseError type.
// options - AccessReviewDefaultSettingsClientGetOptions contains the optional parameters for the AccessReviewDefaultSettingsClient.Get
// method.
func (client *AccessReviewDefaultSettingsClient) Get(ctx context.Context, options *AccessReviewDefaultSettingsClientGetOptions) (AccessReviewDefaultSettingsClientGetResponse, error) {
	req, err := client.getCreateRequest(ctx, options)
	if err != nil {
		return AccessReviewDefaultSettingsClientGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return AccessReviewDefaultSettingsClientGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return AccessReviewDefaultSettingsClientGetResponse{}, runtime.NewResponseError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *AccessReviewDefaultSettingsClient) getCreateRequest(ctx context.Context, options *AccessReviewDefaultSettingsClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/accessReviewScheduleSettings/default"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.host, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2018-05-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *AccessReviewDefaultSettingsClient) getHandleResponse(resp *http.Response) (AccessReviewDefaultSettingsClientGetResponse, error) {
	result := AccessReviewDefaultSettingsClientGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.AccessReviewDefaultSettings); err != nil {
		return AccessReviewDefaultSettingsClientGetResponse{}, err
	}
	return result, nil
}

// Put - Get access review default settings for the subscription
// If the operation fails it returns an *azcore.ResponseError type.
// properties - Access review schedule settings.
// options - AccessReviewDefaultSettingsClientPutOptions contains the optional parameters for the AccessReviewDefaultSettingsClient.Put
// method.
func (client *AccessReviewDefaultSettingsClient) Put(ctx context.Context, properties AccessReviewScheduleSettings, options *AccessReviewDefaultSettingsClientPutOptions) (AccessReviewDefaultSettingsClientPutResponse, error) {
	req, err := client.putCreateRequest(ctx, properties, options)
	if err != nil {
		return AccessReviewDefaultSettingsClientPutResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return AccessReviewDefaultSettingsClientPutResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return AccessReviewDefaultSettingsClientPutResponse{}, runtime.NewResponseError(resp)
	}
	return client.putHandleResponse(resp)
}

// putCreateRequest creates the Put request.
func (client *AccessReviewDefaultSettingsClient) putCreateRequest(ctx context.Context, properties AccessReviewScheduleSettings, options *AccessReviewDefaultSettingsClientPutOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/accessReviewScheduleSettings/default"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.host, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2018-05-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, properties)
}

// putHandleResponse handles the Put response.
func (client *AccessReviewDefaultSettingsClient) putHandleResponse(resp *http.Response) (AccessReviewDefaultSettingsClientPutResponse, error) {
	result := AccessReviewDefaultSettingsClientPutResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.AccessReviewDefaultSettings); err != nil {
		return AccessReviewDefaultSettingsClientPutResponse{}, err
	}
	return result, nil
}
