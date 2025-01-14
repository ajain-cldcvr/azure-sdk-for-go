package synapse

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
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

// SparkConfigurationsClient is the azure Synapse Analytics Management Client
type SparkConfigurationsClient struct {
	BaseClient
}

// NewSparkConfigurationsClient creates an instance of the SparkConfigurationsClient client.
func NewSparkConfigurationsClient(subscriptionID string) SparkConfigurationsClient {
	return NewSparkConfigurationsClientWithBaseURI(DefaultBaseURI, subscriptionID)
}

// NewSparkConfigurationsClientWithBaseURI creates an instance of the SparkConfigurationsClient client using a custom
// endpoint.  Use this when interacting with an Azure cloud that uses a non-standard base URI (sovereign clouds, Azure
// stack).
func NewSparkConfigurationsClientWithBaseURI(baseURI string, subscriptionID string) SparkConfigurationsClient {
	return SparkConfigurationsClient{NewWithBaseURI(baseURI, subscriptionID)}
}

// ListByWorkspace list sparkConfigurations in a workspace.
// Parameters:
// resourceGroupName - the name of the resource group. The name is case insensitive.
// workspaceName - the name of the workspace
func (client SparkConfigurationsClient) ListByWorkspace(ctx context.Context, resourceGroupName string, workspaceName string) (result SparkConfigurationListResponsePage, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/SparkConfigurationsClient.ListByWorkspace")
		defer func() {
			sc := -1
			if result.sclr.Response.Response != nil {
				sc = result.sclr.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	if err := validation.Validate([]validation.Validation{
		{TargetValue: client.SubscriptionID,
			Constraints: []validation.Constraint{{Target: "client.SubscriptionID", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: resourceGroupName,
			Constraints: []validation.Constraint{{Target: "resourceGroupName", Name: validation.MaxLength, Rule: 90, Chain: nil},
				{Target: "resourceGroupName", Name: validation.MinLength, Rule: 1, Chain: nil}}}}); err != nil {
		return result, validation.NewError("synapse.SparkConfigurationsClient", "ListByWorkspace", err.Error())
	}

	result.fn = client.listByWorkspaceNextResults
	req, err := client.ListByWorkspacePreparer(ctx, resourceGroupName, workspaceName)
	if err != nil {
		err = autorest.NewErrorWithError(err, "synapse.SparkConfigurationsClient", "ListByWorkspace", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListByWorkspaceSender(req)
	if err != nil {
		result.sclr.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "synapse.SparkConfigurationsClient", "ListByWorkspace", resp, "Failure sending request")
		return
	}

	result.sclr, err = client.ListByWorkspaceResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "synapse.SparkConfigurationsClient", "ListByWorkspace", resp, "Failure responding to request")
		return
	}
	if result.sclr.hasNextLink() && result.sclr.IsEmpty() {
		err = result.NextWithContext(ctx)
		return
	}

	return
}

// ListByWorkspacePreparer prepares the ListByWorkspace request.
func (client SparkConfigurationsClient) ListByWorkspacePreparer(ctx context.Context, resourceGroupName string, workspaceName string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
		"workspaceName":     autorest.Encode("path", workspaceName),
	}

	const APIVersion = "2021-06-01-preview"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Synapse/workspaces/{workspaceName}/sparkconfigurations", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// ListByWorkspaceSender sends the ListByWorkspace request. The method will close the
// http.Response Body if it receives an error.
func (client SparkConfigurationsClient) ListByWorkspaceSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, azure.DoRetryWithRegistration(client.Client))
}

// ListByWorkspaceResponder handles the response to the ListByWorkspace request. The method always
// closes the http.Response Body.
func (client SparkConfigurationsClient) ListByWorkspaceResponder(resp *http.Response) (result SparkConfigurationListResponse, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// listByWorkspaceNextResults retrieves the next set of results, if any.
func (client SparkConfigurationsClient) listByWorkspaceNextResults(ctx context.Context, lastResults SparkConfigurationListResponse) (result SparkConfigurationListResponse, err error) {
	req, err := lastResults.sparkConfigurationListResponsePreparer(ctx)
	if err != nil {
		return result, autorest.NewErrorWithError(err, "synapse.SparkConfigurationsClient", "listByWorkspaceNextResults", nil, "Failure preparing next results request")
	}
	if req == nil {
		return
	}
	resp, err := client.ListByWorkspaceSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		return result, autorest.NewErrorWithError(err, "synapse.SparkConfigurationsClient", "listByWorkspaceNextResults", resp, "Failure sending next results request")
	}
	result, err = client.ListByWorkspaceResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "synapse.SparkConfigurationsClient", "listByWorkspaceNextResults", resp, "Failure responding to next results request")
	}
	return
}

// ListByWorkspaceComplete enumerates all values, automatically crossing page boundaries as required.
func (client SparkConfigurationsClient) ListByWorkspaceComplete(ctx context.Context, resourceGroupName string, workspaceName string) (result SparkConfigurationListResponseIterator, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/SparkConfigurationsClient.ListByWorkspace")
		defer func() {
			sc := -1
			if result.Response().Response.Response != nil {
				sc = result.page.Response().Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	result.page, err = client.ListByWorkspace(ctx, resourceGroupName, workspaceName)
	return
}
