package digitaltwins

// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"context"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/validation"
	"github.com/Azure/go-autorest/tracing"
	"net/http"
)

// EventRoutesClient is the a service for managing and querying digital twins and digital twin models.
type EventRoutesClient struct {
	BaseClient
}

// NewEventRoutesClient creates an instance of the EventRoutesClient client.
func NewEventRoutesClient() EventRoutesClient {
	return NewEventRoutesClientWithBaseURI(DefaultBaseURI)
}

// NewEventRoutesClientWithBaseURI creates an instance of the EventRoutesClient client using a custom endpoint.  Use
// this when interacting with an Azure cloud that uses a non-standard base URI (sovereign clouds, Azure stack).
func NewEventRoutesClientWithBaseURI(baseURI string) EventRoutesClient {
	return EventRoutesClient{NewWithBaseURI(baseURI)}
}

// Add adds or replaces an event route.
// Status codes:
// 200 (OK): Success.
// 400 (Bad Request): The request is invalid.
// Parameters:
// ID - the id for an event route. The id is unique within event routes and case sensitive.
// eventRoute - the event route data
func (client EventRoutesClient) Add(ctx context.Context, ID string, eventRoute *EventRoute) (result autorest.Response, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/EventRoutesClient.Add")
		defer func() {
			sc := -1
			if result.Response != nil {
				sc = result.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	if err := validation.Validate([]validation.Validation{
		{TargetValue: eventRoute,
			Constraints: []validation.Constraint{{Target: "eventRoute", Name: validation.Null, Rule: false,
				Chain: []validation.Constraint{{Target: "eventRoute.EndpointName", Name: validation.Null, Rule: true, Chain: nil}}}}}}); err != nil {
		return result, validation.NewError("digitaltwins.EventRoutesClient", "Add", err.Error())
	}

	req, err := client.AddPreparer(ctx, ID, eventRoute)
	if err != nil {
		err = autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "Add", nil, "Failure preparing request")
		return
	}

	resp, err := client.AddSender(req)
	if err != nil {
		result.Response = resp
		err = autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "Add", resp, "Failure sending request")
		return
	}

	result, err = client.AddResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "Add", resp, "Failure responding to request")
		return
	}

	return
}

// AddPreparer prepares the Add request.
func (client EventRoutesClient) AddPreparer(ctx context.Context, ID string, eventRoute *EventRoute) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"id": autorest.Encode("path", ID),
	}

	const APIVersion = "2020-05-31-preview"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	eventRoute.ID = nil
	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPut(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/eventroutes/{id}", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	if eventRoute != nil {
		preparer = autorest.DecoratePreparer(preparer,
			autorest.WithJSON(eventRoute))
	}
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// AddSender sends the Add request. The method will close the
// http.Response Body if it receives an error.
func (client EventRoutesClient) AddSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
}

// AddResponder handles the response to the Add request. The method always
// closes the http.Response Body.
func (client EventRoutesClient) AddResponder(resp *http.Response) (result autorest.Response, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusNoContent),
		autorest.ByClosing())
	result.Response = resp
	return
}

// Delete deletes an event route.
// Status codes:
// 200 (OK): Success.
// 404 (Not Found): There is no event route with the provided id.
// Parameters:
// ID - the id for an event route. The id is unique within event routes and case sensitive.
func (client EventRoutesClient) Delete(ctx context.Context, ID string) (result autorest.Response, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/EventRoutesClient.Delete")
		defer func() {
			sc := -1
			if result.Response != nil {
				sc = result.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	req, err := client.DeletePreparer(ctx, ID)
	if err != nil {
		err = autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "Delete", nil, "Failure preparing request")
		return
	}

	resp, err := client.DeleteSender(req)
	if err != nil {
		result.Response = resp
		err = autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "Delete", resp, "Failure sending request")
		return
	}

	result, err = client.DeleteResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "Delete", resp, "Failure responding to request")
		return
	}

	return
}

// DeletePreparer prepares the Delete request.
func (client EventRoutesClient) DeletePreparer(ctx context.Context, ID string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"id": autorest.Encode("path", ID),
	}

	const APIVersion = "2020-05-31-preview"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsDelete(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/eventroutes/{id}", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// DeleteSender sends the Delete request. The method will close the
// http.Response Body if it receives an error.
func (client EventRoutesClient) DeleteSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
}

// DeleteResponder handles the response to the Delete request. The method always
// closes the http.Response Body.
func (client EventRoutesClient) DeleteResponder(resp *http.Response) (result autorest.Response, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusNoContent),
		autorest.ByClosing())
	result.Response = resp
	return
}

// GetByID retrieves an event route.
// Status codes:
// 200 (OK): Success.
// 404 (Not Found): There is no event route with the provided id.
// Parameters:
// ID - the id for an event route. The id is unique within event routes and case sensitive.
func (client EventRoutesClient) GetByID(ctx context.Context, ID string) (result EventRoute, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/EventRoutesClient.GetByID")
		defer func() {
			sc := -1
			if result.Response.Response != nil {
				sc = result.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	req, err := client.GetByIDPreparer(ctx, ID)
	if err != nil {
		err = autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "GetByID", nil, "Failure preparing request")
		return
	}

	resp, err := client.GetByIDSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "GetByID", resp, "Failure sending request")
		return
	}

	result, err = client.GetByIDResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "GetByID", resp, "Failure responding to request")
		return
	}

	return
}

// GetByIDPreparer prepares the GetByID request.
func (client EventRoutesClient) GetByIDPreparer(ctx context.Context, ID string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"id": autorest.Encode("path", ID),
	}

	const APIVersion = "2020-05-31-preview"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/eventroutes/{id}", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// GetByIDSender sends the GetByID request. The method will close the
// http.Response Body if it receives an error.
func (client EventRoutesClient) GetByIDSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
}

// GetByIDResponder handles the response to the GetByID request. The method always
// closes the http.Response Body.
func (client EventRoutesClient) GetByIDResponder(resp *http.Response) (result EventRoute, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// List retrieves all event routes.
// Status codes:
// 200 (OK): Success.
// 400 (Bad Request): The request is invalid.
// Parameters:
// maxItemCount - the maximum number of items to retrieve per request. The server may choose to return less
// than the requested max.
func (client EventRoutesClient) List(ctx context.Context, maxItemCount *int32) (result EventRouteCollectionPage, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/EventRoutesClient.List")
		defer func() {
			sc := -1
			if result.erc.Response.Response != nil {
				sc = result.erc.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	result.fn = client.listNextResults
	req, err := client.ListPreparer(ctx, maxItemCount)
	if err != nil {
		err = autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "List", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListSender(req)
	if err != nil {
		result.erc.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "List", resp, "Failure sending request")
		return
	}

	result.erc, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "List", resp, "Failure responding to request")
		return
	}
	if result.erc.hasNextLink() && result.erc.IsEmpty() {
		err = result.NextWithContext(ctx)
		return
	}

	return
}

// ListPreparer prepares the List request.
func (client EventRoutesClient) ListPreparer(ctx context.Context, maxItemCount *int32) (*http.Request, error) {
	const APIVersion = "2020-05-31-preview"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPath("/eventroutes"),
		autorest.WithQueryParameters(queryParameters))
	if maxItemCount != nil {
		preparer = autorest.DecoratePreparer(preparer,
			autorest.WithHeader("x-ms-max-item-count", autorest.String(*maxItemCount)))
	} else {
		preparer = autorest.DecoratePreparer(preparer,
			autorest.WithHeader("x-ms-max-item-count", autorest.String(-1)))
	}
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// ListSender sends the List request. The method will close the
// http.Response Body if it receives an error.
func (client EventRoutesClient) ListSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
}

// ListResponder handles the response to the List request. The method always
// closes the http.Response Body.
func (client EventRoutesClient) ListResponder(resp *http.Response) (result EventRouteCollection, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// listNextResults retrieves the next set of results, if any.
func (client EventRoutesClient) listNextResults(ctx context.Context, lastResults EventRouteCollection) (result EventRouteCollection, err error) {
	req, err := lastResults.eventRouteCollectionPreparer(ctx)
	if err != nil {
		return result, autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "listNextResults", nil, "Failure preparing next results request")
	}
	if req == nil {
		return
	}
	resp, err := client.ListSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		return result, autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "listNextResults", resp, "Failure sending next results request")
	}
	result, err = client.ListResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "digitaltwins.EventRoutesClient", "listNextResults", resp, "Failure responding to next results request")
	}
	return
}

// ListComplete enumerates all values, automatically crossing page boundaries as required.
func (client EventRoutesClient) ListComplete(ctx context.Context, maxItemCount *int32) (result EventRouteCollectionIterator, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/EventRoutesClient.List")
		defer func() {
			sc := -1
			if result.Response().Response.Response != nil {
				sc = result.page.Response().Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	result.page, err = client.List(ctx, maxItemCount)
	return
}