// +build go1.13

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armstorage

import (
	"context"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/armcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// PrivateLinkResourcesClient contains the methods for the PrivateLinkResources group.
// Don't use this type directly, use NewPrivateLinkResourcesClient() instead.
type PrivateLinkResourcesClient struct {
	con            *armcore.Connection
	subscriptionID string
}

// NewPrivateLinkResourcesClient creates a new instance of PrivateLinkResourcesClient with the specified values.
func NewPrivateLinkResourcesClient(con *armcore.Connection, subscriptionID string) *PrivateLinkResourcesClient {
	return &PrivateLinkResourcesClient{con: con, subscriptionID: subscriptionID}
}

// ListByStorageAccount - Gets the private link resources that need to be created for a storage account.
func (client *PrivateLinkResourcesClient) ListByStorageAccount(ctx context.Context, resourceGroupName string, accountName string, options *PrivateLinkResourcesListByStorageAccountOptions) (PrivateLinkResourceListResultResponse, error) {
	req, err := client.listByStorageAccountCreateRequest(ctx, resourceGroupName, accountName, options)
	if err != nil {
		return PrivateLinkResourceListResultResponse{}, err
	}
	resp, err := client.con.Pipeline().Do(req)
	if err != nil {
		return PrivateLinkResourceListResultResponse{}, err
	}
	if !resp.HasStatusCode(http.StatusOK) {
		return PrivateLinkResourceListResultResponse{}, client.listByStorageAccountHandleError(resp)
	}
	return client.listByStorageAccountHandleResponse(resp)
}

// listByStorageAccountCreateRequest creates the ListByStorageAccount request.
func (client *PrivateLinkResourcesClient) listByStorageAccountCreateRequest(ctx context.Context, resourceGroupName string, accountName string, options *PrivateLinkResourcesListByStorageAccountOptions) (*azcore.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Storage/storageAccounts/{accountName}/privateLinkResources"
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := azcore.NewRequest(ctx, http.MethodGet, azcore.JoinPaths(client.con.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	req.Telemetry(telemetryInfo)
	query := req.URL.Query()
	query.Set("api-version", "2019-06-01")
	req.URL.RawQuery = query.Encode()
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// listByStorageAccountHandleResponse handles the ListByStorageAccount response.
func (client *PrivateLinkResourcesClient) listByStorageAccountHandleResponse(resp *azcore.Response) (PrivateLinkResourceListResultResponse, error) {
	var val *PrivateLinkResourceListResult
	if err := resp.UnmarshalAsJSON(&val); err != nil {
		return PrivateLinkResourceListResultResponse{}, err
	}
	return PrivateLinkResourceListResultResponse{RawResponse: resp.Response, PrivateLinkResourceListResult: val}, nil
}

// listByStorageAccountHandleError handles the ListByStorageAccount error response.
func (client *PrivateLinkResourcesClient) listByStorageAccountHandleError(resp *azcore.Response) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s; failed to read response body: %w", resp.Status, err)
	}
	if len(body) == 0 {
		return azcore.NewResponseError(errors.New(resp.Status), resp.Response)
	}
	return azcore.NewResponseError(errors.New(string(body)), resp.Response)
}