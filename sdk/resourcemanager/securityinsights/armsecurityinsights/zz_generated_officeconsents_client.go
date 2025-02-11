//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armsecurityinsights

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

// OfficeConsentsClient contains the methods for the OfficeConsents group.
// Don't use this type directly, use NewOfficeConsentsClient() instead.
type OfficeConsentsClient struct {
	host           string
	subscriptionID string
	pl             runtime.Pipeline
}

// NewOfficeConsentsClient creates a new instance of OfficeConsentsClient with the specified values.
// subscriptionID - The ID of the target subscription.
// credential - used to authorize requests. Usually a credential from azidentity.
// options - pass nil to accept the default values.
func NewOfficeConsentsClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *OfficeConsentsClient {
	if options == nil {
		options = &arm.ClientOptions{}
	}
	ep := options.Endpoint
	if len(ep) == 0 {
		ep = arm.AzurePublicCloud
	}
	client := &OfficeConsentsClient{
		subscriptionID: subscriptionID,
		host:           string(ep),
		pl:             armruntime.NewPipeline(moduleName, moduleVersion, credential, runtime.PipelineOptions{}, options),
	}
	return client
}

// Delete - Delete the office365 consent.
// If the operation fails it returns an *azcore.ResponseError type.
// resourceGroupName - The name of the resource group. The name is case insensitive.
// workspaceName - The name of the workspace.
// consentID - consent ID
// options - OfficeConsentsClientDeleteOptions contains the optional parameters for the OfficeConsentsClient.Delete method.
func (client *OfficeConsentsClient) Delete(ctx context.Context, resourceGroupName string, workspaceName string, consentID string, options *OfficeConsentsClientDeleteOptions) (OfficeConsentsClientDeleteResponse, error) {
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, workspaceName, consentID, options)
	if err != nil {
		return OfficeConsentsClientDeleteResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return OfficeConsentsClientDeleteResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusNoContent) {
		return OfficeConsentsClientDeleteResponse{}, runtime.NewResponseError(resp)
	}
	return OfficeConsentsClientDeleteResponse{RawResponse: resp}, nil
}

// deleteCreateRequest creates the Delete request.
func (client *OfficeConsentsClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, workspaceName string, consentID string, options *OfficeConsentsClientDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/officeConsents/{consentId}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if workspaceName == "" {
		return nil, errors.New("parameter workspaceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{workspaceName}", url.PathEscape(workspaceName))
	if consentID == "" {
		return nil, errors.New("parameter consentID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{consentId}", url.PathEscape(consentID))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.host, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-10-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// Get - Gets an office365 consent.
// If the operation fails it returns an *azcore.ResponseError type.
// resourceGroupName - The name of the resource group. The name is case insensitive.
// workspaceName - The name of the workspace.
// consentID - consent ID
// options - OfficeConsentsClientGetOptions contains the optional parameters for the OfficeConsentsClient.Get method.
func (client *OfficeConsentsClient) Get(ctx context.Context, resourceGroupName string, workspaceName string, consentID string, options *OfficeConsentsClientGetOptions) (OfficeConsentsClientGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, workspaceName, consentID, options)
	if err != nil {
		return OfficeConsentsClientGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return OfficeConsentsClientGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return OfficeConsentsClientGetResponse{}, runtime.NewResponseError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *OfficeConsentsClient) getCreateRequest(ctx context.Context, resourceGroupName string, workspaceName string, consentID string, options *OfficeConsentsClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/officeConsents/{consentId}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if workspaceName == "" {
		return nil, errors.New("parameter workspaceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{workspaceName}", url.PathEscape(workspaceName))
	if consentID == "" {
		return nil, errors.New("parameter consentID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{consentId}", url.PathEscape(consentID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.host, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-10-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *OfficeConsentsClient) getHandleResponse(resp *http.Response) (OfficeConsentsClientGetResponse, error) {
	result := OfficeConsentsClientGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.OfficeConsent); err != nil {
		return OfficeConsentsClientGetResponse{}, err
	}
	return result, nil
}

// List - Gets all office365 consents.
// If the operation fails it returns an *azcore.ResponseError type.
// resourceGroupName - The name of the resource group. The name is case insensitive.
// workspaceName - The name of the workspace.
// options - OfficeConsentsClientListOptions contains the optional parameters for the OfficeConsentsClient.List method.
func (client *OfficeConsentsClient) List(resourceGroupName string, workspaceName string, options *OfficeConsentsClientListOptions) *OfficeConsentsClientListPager {
	return &OfficeConsentsClientListPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listCreateRequest(ctx, resourceGroupName, workspaceName, options)
		},
		advancer: func(ctx context.Context, resp OfficeConsentsClientListResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.OfficeConsentList.NextLink)
		},
	}
}

// listCreateRequest creates the List request.
func (client *OfficeConsentsClient) listCreateRequest(ctx context.Context, resourceGroupName string, workspaceName string, options *OfficeConsentsClientListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/officeConsents"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if workspaceName == "" {
		return nil, errors.New("parameter workspaceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{workspaceName}", url.PathEscape(workspaceName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.host, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-10-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listHandleResponse handles the List response.
func (client *OfficeConsentsClient) listHandleResponse(resp *http.Response) (OfficeConsentsClientListResponse, error) {
	result := OfficeConsentsClientListResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.OfficeConsentList); err != nil {
		return OfficeConsentsClientListResponse{}, err
	}
	return result, nil
}
