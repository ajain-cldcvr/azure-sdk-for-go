//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armconsumption

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
)

// ReservationsDetailsClient contains the methods for the ReservationsDetails group.
// Don't use this type directly, use NewReservationsDetailsClient() instead.
type ReservationsDetailsClient struct {
	ep string
	pl runtime.Pipeline
}

// NewReservationsDetailsClient creates a new instance of ReservationsDetailsClient with the specified values.
func NewReservationsDetailsClient(con *arm.Connection) *ReservationsDetailsClient {
	return &ReservationsDetailsClient{ep: con.Endpoint(), pl: con.NewPipeline(module, version)}
}

// List - Lists the reservations details for the defined scope and provided date range.
// If the operation fails it returns the *ErrorResponse error type.
func (client *ReservationsDetailsClient) List(scope string, options *ReservationsDetailsListOptions) *ReservationsDetailsListPager {
	return &ReservationsDetailsListPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listCreateRequest(ctx, scope, options)
		},
		advancer: func(ctx context.Context, resp ReservationsDetailsListResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.ReservationDetailsListResult.NextLink)
		},
	}
}

// listCreateRequest creates the List request.
func (client *ReservationsDetailsClient) listCreateRequest(ctx context.Context, scope string, options *ReservationsDetailsListOptions) (*policy.Request, error) {
	urlPath := "/{scope}/providers/Microsoft.Consumption/reservationDetails"
	if scope == "" {
		return nil, errors.New("parameter scope cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{scope}", scope)
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	if options != nil && options.StartDate != nil {
		reqQP.Set("startDate", *options.StartDate)
	}
	if options != nil && options.EndDate != nil {
		reqQP.Set("endDate", *options.EndDate)
	}
	if options != nil && options.Filter != nil {
		reqQP.Set("$filter", *options.Filter)
	}
	if options != nil && options.ReservationID != nil {
		reqQP.Set("reservationId", *options.ReservationID)
	}
	if options != nil && options.ReservationOrderID != nil {
		reqQP.Set("reservationOrderId", *options.ReservationOrderID)
	}
	reqQP.Set("api-version", "2021-10-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listHandleResponse handles the List response.
func (client *ReservationsDetailsClient) listHandleResponse(resp *http.Response) (ReservationsDetailsListResponse, error) {
	result := ReservationsDetailsListResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.ReservationDetailsListResult); err != nil {
		return ReservationsDetailsListResponse{}, err
	}
	return result, nil
}

// listHandleError handles the List error response.
func (client *ReservationsDetailsClient) listHandleError(resp *http.Response) error {
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

// ListByReservationOrder - Lists the reservations details for provided date range.
// If the operation fails it returns the *ErrorResponse error type.
func (client *ReservationsDetailsClient) ListByReservationOrder(reservationOrderID string, filter string, options *ReservationsDetailsListByReservationOrderOptions) *ReservationsDetailsListByReservationOrderPager {
	return &ReservationsDetailsListByReservationOrderPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listByReservationOrderCreateRequest(ctx, reservationOrderID, filter, options)
		},
		advancer: func(ctx context.Context, resp ReservationsDetailsListByReservationOrderResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.ReservationDetailsListResult.NextLink)
		},
	}
}

// listByReservationOrderCreateRequest creates the ListByReservationOrder request.
func (client *ReservationsDetailsClient) listByReservationOrderCreateRequest(ctx context.Context, reservationOrderID string, filter string, options *ReservationsDetailsListByReservationOrderOptions) (*policy.Request, error) {
	urlPath := "/providers/Microsoft.Capacity/reservationorders/{reservationOrderId}/providers/Microsoft.Consumption/reservationDetails"
	if reservationOrderID == "" {
		return nil, errors.New("parameter reservationOrderID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{reservationOrderId}", url.PathEscape(reservationOrderID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("$filter", filter)
	reqQP.Set("api-version", "2021-10-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listByReservationOrderHandleResponse handles the ListByReservationOrder response.
func (client *ReservationsDetailsClient) listByReservationOrderHandleResponse(resp *http.Response) (ReservationsDetailsListByReservationOrderResponse, error) {
	result := ReservationsDetailsListByReservationOrderResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.ReservationDetailsListResult); err != nil {
		return ReservationsDetailsListByReservationOrderResponse{}, err
	}
	return result, nil
}

// listByReservationOrderHandleError handles the ListByReservationOrder error response.
func (client *ReservationsDetailsClient) listByReservationOrderHandleError(resp *http.Response) error {
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

// ListByReservationOrderAndReservation - Lists the reservations details for provided date range.
// If the operation fails it returns the *ErrorResponse error type.
func (client *ReservationsDetailsClient) ListByReservationOrderAndReservation(reservationOrderID string, reservationID string, filter string, options *ReservationsDetailsListByReservationOrderAndReservationOptions) *ReservationsDetailsListByReservationOrderAndReservationPager {
	return &ReservationsDetailsListByReservationOrderAndReservationPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listByReservationOrderAndReservationCreateRequest(ctx, reservationOrderID, reservationID, filter, options)
		},
		advancer: func(ctx context.Context, resp ReservationsDetailsListByReservationOrderAndReservationResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.ReservationDetailsListResult.NextLink)
		},
	}
}

// listByReservationOrderAndReservationCreateRequest creates the ListByReservationOrderAndReservation request.
func (client *ReservationsDetailsClient) listByReservationOrderAndReservationCreateRequest(ctx context.Context, reservationOrderID string, reservationID string, filter string, options *ReservationsDetailsListByReservationOrderAndReservationOptions) (*policy.Request, error) {
	urlPath := "/providers/Microsoft.Capacity/reservationorders/{reservationOrderId}/reservations/{reservationId}/providers/Microsoft.Consumption/reservationDetails"
	if reservationOrderID == "" {
		return nil, errors.New("parameter reservationOrderID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{reservationOrderId}", url.PathEscape(reservationOrderID))
	if reservationID == "" {
		return nil, errors.New("parameter reservationID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{reservationId}", url.PathEscape(reservationID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("$filter", filter)
	reqQP.Set("api-version", "2021-10-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listByReservationOrderAndReservationHandleResponse handles the ListByReservationOrderAndReservation response.
func (client *ReservationsDetailsClient) listByReservationOrderAndReservationHandleResponse(resp *http.Response) (ReservationsDetailsListByReservationOrderAndReservationResponse, error) {
	result := ReservationsDetailsListByReservationOrderAndReservationResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.ReservationDetailsListResult); err != nil {
		return ReservationsDetailsListByReservationOrderAndReservationResponse{}, err
	}
	return result, nil
}

// listByReservationOrderAndReservationHandleError handles the ListByReservationOrderAndReservation error response.
func (client *ReservationsDetailsClient) listByReservationOrderAndReservationHandleError(resp *http.Response) error {
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