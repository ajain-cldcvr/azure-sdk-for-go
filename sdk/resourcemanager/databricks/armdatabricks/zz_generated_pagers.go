//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armdatabricks

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"reflect"
)

// OperationsClientListPager provides operations for iterating over paged responses.
type OperationsClientListPager struct {
	client    *OperationsClient
	current   OperationsClientListResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, OperationsClientListResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *OperationsClientListPager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *OperationsClientListPager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.OperationListResult.NextLink == nil || len(*p.current.OperationListResult.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = runtime.NewResponseError(resp)
		return false
	}
	result, err := p.client.listHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current OperationsClientListResponse page.
func (p *OperationsClientListPager) PageResponse() OperationsClientListResponse {
	return p.current
}

// PrivateEndpointConnectionsClientListPager provides operations for iterating over paged responses.
type PrivateEndpointConnectionsClientListPager struct {
	client    *PrivateEndpointConnectionsClient
	current   PrivateEndpointConnectionsClientListResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, PrivateEndpointConnectionsClientListResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *PrivateEndpointConnectionsClientListPager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *PrivateEndpointConnectionsClientListPager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.PrivateEndpointConnectionsList.NextLink == nil || len(*p.current.PrivateEndpointConnectionsList.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = runtime.NewResponseError(resp)
		return false
	}
	result, err := p.client.listHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current PrivateEndpointConnectionsClientListResponse page.
func (p *PrivateEndpointConnectionsClientListPager) PageResponse() PrivateEndpointConnectionsClientListResponse {
	return p.current
}

// PrivateLinkResourcesClientListPager provides operations for iterating over paged responses.
type PrivateLinkResourcesClientListPager struct {
	client    *PrivateLinkResourcesClient
	current   PrivateLinkResourcesClientListResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, PrivateLinkResourcesClientListResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *PrivateLinkResourcesClientListPager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *PrivateLinkResourcesClientListPager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.PrivateLinkResourcesList.NextLink == nil || len(*p.current.PrivateLinkResourcesList.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = runtime.NewResponseError(resp)
		return false
	}
	result, err := p.client.listHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current PrivateLinkResourcesClientListResponse page.
func (p *PrivateLinkResourcesClientListPager) PageResponse() PrivateLinkResourcesClientListResponse {
	return p.current
}

// VNetPeeringClientListByWorkspacePager provides operations for iterating over paged responses.
type VNetPeeringClientListByWorkspacePager struct {
	client    *VNetPeeringClient
	current   VNetPeeringClientListByWorkspaceResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, VNetPeeringClientListByWorkspaceResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *VNetPeeringClientListByWorkspacePager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *VNetPeeringClientListByWorkspacePager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.VirtualNetworkPeeringList.NextLink == nil || len(*p.current.VirtualNetworkPeeringList.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = runtime.NewResponseError(resp)
		return false
	}
	result, err := p.client.listByWorkspaceHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current VNetPeeringClientListByWorkspaceResponse page.
func (p *VNetPeeringClientListByWorkspacePager) PageResponse() VNetPeeringClientListByWorkspaceResponse {
	return p.current
}

// WorkspacesClientListByResourceGroupPager provides operations for iterating over paged responses.
type WorkspacesClientListByResourceGroupPager struct {
	client    *WorkspacesClient
	current   WorkspacesClientListByResourceGroupResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, WorkspacesClientListByResourceGroupResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *WorkspacesClientListByResourceGroupPager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *WorkspacesClientListByResourceGroupPager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.WorkspaceListResult.NextLink == nil || len(*p.current.WorkspaceListResult.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = runtime.NewResponseError(resp)
		return false
	}
	result, err := p.client.listByResourceGroupHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current WorkspacesClientListByResourceGroupResponse page.
func (p *WorkspacesClientListByResourceGroupPager) PageResponse() WorkspacesClientListByResourceGroupResponse {
	return p.current
}

// WorkspacesClientListBySubscriptionPager provides operations for iterating over paged responses.
type WorkspacesClientListBySubscriptionPager struct {
	client    *WorkspacesClient
	current   WorkspacesClientListBySubscriptionResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, WorkspacesClientListBySubscriptionResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *WorkspacesClientListBySubscriptionPager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *WorkspacesClientListBySubscriptionPager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.WorkspaceListResult.NextLink == nil || len(*p.current.WorkspaceListResult.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = runtime.NewResponseError(resp)
		return false
	}
	result, err := p.client.listBySubscriptionHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current WorkspacesClientListBySubscriptionResponse page.
func (p *WorkspacesClientListBySubscriptionPager) PageResponse() WorkspacesClientListBySubscriptionResponse {
	return p.current
}
