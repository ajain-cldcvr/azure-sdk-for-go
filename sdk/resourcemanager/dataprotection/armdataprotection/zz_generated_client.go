//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armdataprotection

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

// Client contains the methods for the DataProtection group.
// Don't use this type directly, use NewClient() instead.
type Client struct {
	host           string
	subscriptionID string
	pl             runtime.Pipeline
}

// NewClient creates a new instance of Client with the specified values.
// subscriptionID - The subscription Id.
// credential - used to authorize requests. Usually a credential from azidentity.
// options - pass nil to accept the default values.
func NewClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *Client {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Endpoint) == 0 {
		cp.Endpoint = arm.AzurePublicCloud
	}
	client := &Client{
		subscriptionID: subscriptionID,
		host:           string(cp.Endpoint),
		pl:             armruntime.NewPipeline(moduleName, moduleVersion, credential, runtime.PipelineOptions{}, &cp),
	}
	return client
}

// CheckFeatureSupport - Validates if a feature is supported
// If the operation fails it returns an *azcore.ResponseError type.
// parameters - Feature support request object
// options - ClientCheckFeatureSupportOptions contains the optional parameters for the Client.CheckFeatureSupport method.
func (client *Client) CheckFeatureSupport(ctx context.Context, location string, parameters FeatureValidationRequestBaseClassification, options *ClientCheckFeatureSupportOptions) (ClientCheckFeatureSupportResponse, error) {
	req, err := client.checkFeatureSupportCreateRequest(ctx, location, parameters, options)
	if err != nil {
		return ClientCheckFeatureSupportResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return ClientCheckFeatureSupportResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return ClientCheckFeatureSupportResponse{}, runtime.NewResponseError(resp)
	}
	return client.checkFeatureSupportHandleResponse(resp)
}

// checkFeatureSupportCreateRequest creates the CheckFeatureSupport request.
func (client *Client) checkFeatureSupportCreateRequest(ctx context.Context, location string, parameters FeatureValidationRequestBaseClassification, options *ClientCheckFeatureSupportOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.DataProtection/locations/{location}/checkFeatureSupport"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if location == "" {
		return nil, errors.New("parameter location cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{location}", url.PathEscape(location))
	req, err := runtime.NewRequest(ctx, http.MethodPost, runtime.JoinPaths(client.host, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// checkFeatureSupportHandleResponse handles the CheckFeatureSupport response.
func (client *Client) checkFeatureSupportHandleResponse(resp *http.Response) (ClientCheckFeatureSupportResponse, error) {
	result := ClientCheckFeatureSupportResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result); err != nil {
		return ClientCheckFeatureSupportResponse{}, err
	}
	return result, nil
}
