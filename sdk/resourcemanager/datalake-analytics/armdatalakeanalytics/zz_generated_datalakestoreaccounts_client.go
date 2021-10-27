//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armdatalakeanalytics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
)

// DataLakeStoreAccountsClient contains the methods for the DataLakeStoreAccounts group.
// Don't use this type directly, use NewDataLakeStoreAccountsClient() instead.
type DataLakeStoreAccountsClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewDataLakeStoreAccountsClient creates a new instance of DataLakeStoreAccountsClient with the specified values.
func NewDataLakeStoreAccountsClient(con *arm.Connection, subscriptionID string) *DataLakeStoreAccountsClient {
	return &DataLakeStoreAccountsClient{ep: con.Endpoint(), pl: con.NewPipeline(module, version), subscriptionID: subscriptionID}
}

// Add - Updates the specified Data Lake Analytics account to include the additional Data Lake Store account.
// If the operation fails it returns the *ErrorResponse error type.
func (client *DataLakeStoreAccountsClient) Add(ctx context.Context, resourceGroupName string, accountName string, dataLakeStoreAccountName string, options *DataLakeStoreAccountsAddOptions) (DataLakeStoreAccountsAddResponse, error) {
	req, err := client.addCreateRequest(ctx, resourceGroupName, accountName, dataLakeStoreAccountName, options)
	if err != nil {
		return DataLakeStoreAccountsAddResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return DataLakeStoreAccountsAddResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return DataLakeStoreAccountsAddResponse{}, client.addHandleError(resp)
	}
	return DataLakeStoreAccountsAddResponse{RawResponse: resp}, nil
}

// addCreateRequest creates the Add request.
func (client *DataLakeStoreAccountsClient) addCreateRequest(ctx context.Context, resourceGroupName string, accountName string, dataLakeStoreAccountName string, options *DataLakeStoreAccountsAddOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeAnalytics/accounts/{accountName}/dataLakeStoreAccounts/{dataLakeStoreAccountName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	if dataLakeStoreAccountName == "" {
		return nil, errors.New("parameter dataLakeStoreAccountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{dataLakeStoreAccountName}", url.PathEscape(dataLakeStoreAccountName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-11-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	if options != nil && options.Parameters != nil {
		return req, runtime.MarshalAsJSON(req, *options.Parameters)
	}
	return req, nil
}

// addHandleError handles the Add error response.
func (client *DataLakeStoreAccountsClient) addHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorResponse{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// Delete - Updates the Data Lake Analytics account specified to remove the specified Data Lake Store account.
// If the operation fails it returns the *ErrorResponse error type.
func (client *DataLakeStoreAccountsClient) Delete(ctx context.Context, resourceGroupName string, accountName string, dataLakeStoreAccountName string, options *DataLakeStoreAccountsDeleteOptions) (DataLakeStoreAccountsDeleteResponse, error) {
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, accountName, dataLakeStoreAccountName, options)
	if err != nil {
		return DataLakeStoreAccountsDeleteResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return DataLakeStoreAccountsDeleteResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusNoContent) {
		return DataLakeStoreAccountsDeleteResponse{}, client.deleteHandleError(resp)
	}
	return DataLakeStoreAccountsDeleteResponse{RawResponse: resp}, nil
}

// deleteCreateRequest creates the Delete request.
func (client *DataLakeStoreAccountsClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, accountName string, dataLakeStoreAccountName string, options *DataLakeStoreAccountsDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeAnalytics/accounts/{accountName}/dataLakeStoreAccounts/{dataLakeStoreAccountName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	if dataLakeStoreAccountName == "" {
		return nil, errors.New("parameter dataLakeStoreAccountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{dataLakeStoreAccountName}", url.PathEscape(dataLakeStoreAccountName))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-11-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// deleteHandleError handles the Delete error response.
func (client *DataLakeStoreAccountsClient) deleteHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorResponse{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// Get - Gets the specified Data Lake Store account details in the specified Data Lake Analytics account.
// If the operation fails it returns the *ErrorResponse error type.
func (client *DataLakeStoreAccountsClient) Get(ctx context.Context, resourceGroupName string, accountName string, dataLakeStoreAccountName string, options *DataLakeStoreAccountsGetOptions) (DataLakeStoreAccountsGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, accountName, dataLakeStoreAccountName, options)
	if err != nil {
		return DataLakeStoreAccountsGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return DataLakeStoreAccountsGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return DataLakeStoreAccountsGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *DataLakeStoreAccountsClient) getCreateRequest(ctx context.Context, resourceGroupName string, accountName string, dataLakeStoreAccountName string, options *DataLakeStoreAccountsGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeAnalytics/accounts/{accountName}/dataLakeStoreAccounts/{dataLakeStoreAccountName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	if dataLakeStoreAccountName == "" {
		return nil, errors.New("parameter dataLakeStoreAccountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{dataLakeStoreAccountName}", url.PathEscape(dataLakeStoreAccountName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-11-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *DataLakeStoreAccountsClient) getHandleResponse(resp *http.Response) (DataLakeStoreAccountsGetResponse, error) {
	result := DataLakeStoreAccountsGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.DataLakeStoreAccountInformation); err != nil {
		return DataLakeStoreAccountsGetResponse{}, err
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *DataLakeStoreAccountsClient) getHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorResponse{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// ListByAccount - Gets the first page of Data Lake Store accounts linked to the specified Data Lake Analytics account. The response includes a link to
// the next page, if any.
// If the operation fails it returns the *ErrorResponse error type.
func (client *DataLakeStoreAccountsClient) ListByAccount(resourceGroupName string, accountName string, options *DataLakeStoreAccountsListByAccountOptions) *DataLakeStoreAccountsListByAccountPager {
	return &DataLakeStoreAccountsListByAccountPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listByAccountCreateRequest(ctx, resourceGroupName, accountName, options)
		},
		advancer: func(ctx context.Context, resp DataLakeStoreAccountsListByAccountResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.DataLakeStoreAccountInformationListResult.NextLink)
		},
	}
}

// listByAccountCreateRequest creates the ListByAccount request.
func (client *DataLakeStoreAccountsClient) listByAccountCreateRequest(ctx context.Context, resourceGroupName string, accountName string, options *DataLakeStoreAccountsListByAccountOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataLakeAnalytics/accounts/{accountName}/dataLakeStoreAccounts"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	if options != nil && options.Filter != nil {
		reqQP.Set("$filter", *options.Filter)
	}
	if options != nil && options.Top != nil {
		reqQP.Set("$top", strconv.FormatInt(int64(*options.Top), 10))
	}
	if options != nil && options.Skip != nil {
		reqQP.Set("$skip", strconv.FormatInt(int64(*options.Skip), 10))
	}
	if options != nil && options.Select != nil {
		reqQP.Set("$select", *options.Select)
	}
	if options != nil && options.Orderby != nil {
		reqQP.Set("$orderby", *options.Orderby)
	}
	if options != nil && options.Count != nil {
		reqQP.Set("$count", strconv.FormatBool(*options.Count))
	}
	reqQP.Set("api-version", "2019-11-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listByAccountHandleResponse handles the ListByAccount response.
func (client *DataLakeStoreAccountsClient) listByAccountHandleResponse(resp *http.Response) (DataLakeStoreAccountsListByAccountResponse, error) {
	result := DataLakeStoreAccountsListByAccountResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.DataLakeStoreAccountInformationListResult); err != nil {
		return DataLakeStoreAccountsListByAccountResponse{}, err
	}
	return result, nil
}

// listByAccountHandleError handles the ListByAccount error response.
func (client *DataLakeStoreAccountsClient) listByAccountHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorResponse{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}