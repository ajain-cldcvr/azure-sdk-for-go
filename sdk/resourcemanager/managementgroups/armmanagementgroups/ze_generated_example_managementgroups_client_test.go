//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armmanagementgroups_test

import (
	"context"
	"log"

	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups"
)

// x-ms-original-file: specification/managementgroups/resource-manager/Microsoft.Management/stable/2021-04-01/examples/ListManagementGroups.json
func ExampleClient_List() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armmanagementgroups.NewClient(cred, nil)
	pager := client.List(&armmanagementgroups.ClientListOptions{CacheControl: to.StringPtr("<cache-control>"),
		Skiptoken: nil,
	})
	for {
		nextResult := pager.NextPage(ctx)
		if err := pager.Err(); err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		if !nextResult {
			break
		}
		for _, v := range pager.PageResponse().Value {
			log.Printf("Pager result: %#v\n", v)
		}
	}
}

// x-ms-original-file: specification/managementgroups/resource-manager/Microsoft.Management/stable/2021-04-01/examples/GetManagementGroup.json
func ExampleClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armmanagementgroups.NewClient(cred, nil)
	res, err := client.Get(ctx,
		"<group-id>",
		&armmanagementgroups.ClientGetOptions{Expand: nil,
			Recurse:      nil,
			Filter:       nil,
			CacheControl: to.StringPtr("<cache-control>"),
		})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.ClientGetResult)
}

// x-ms-original-file: specification/managementgroups/resource-manager/Microsoft.Management/stable/2021-04-01/examples/PutManagementGroup.json
func ExampleClient_BeginCreateOrUpdate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armmanagementgroups.NewClient(cred, nil)
	poller, err := client.BeginCreateOrUpdate(ctx,
		"<group-id>",
		armmanagementgroups.CreateManagementGroupRequest{
			Properties: &armmanagementgroups.CreateManagementGroupProperties{
				DisplayName: to.StringPtr("<display-name>"),
				Details: &armmanagementgroups.CreateManagementGroupDetails{
					Parent: &armmanagementgroups.CreateParentGroupInfo{
						ID: to.StringPtr("<id>"),
					},
				},
			},
		},
		&armmanagementgroups.ClientBeginCreateOrUpdateOptions{CacheControl: to.StringPtr("<cache-control>")})
	if err != nil {
		log.Fatal(err)
	}
	res, err := poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.ClientCreateOrUpdateResult)
}

// x-ms-original-file: specification/managementgroups/resource-manager/Microsoft.Management/stable/2021-04-01/examples/PatchManagementGroup.json
func ExampleClient_Update() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armmanagementgroups.NewClient(cred, nil)
	res, err := client.Update(ctx,
		"<group-id>",
		armmanagementgroups.PatchManagementGroupRequest{
			DisplayName:   to.StringPtr("<display-name>"),
			ParentGroupID: to.StringPtr("<parent-group-id>"),
		},
		&armmanagementgroups.ClientUpdateOptions{CacheControl: to.StringPtr("<cache-control>")})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.ClientUpdateResult)
}

// x-ms-original-file: specification/managementgroups/resource-manager/Microsoft.Management/stable/2021-04-01/examples/DeleteManagementGroup.json
func ExampleClient_BeginDelete() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armmanagementgroups.NewClient(cred, nil)
	poller, err := client.BeginDelete(ctx,
		"<group-id>",
		&armmanagementgroups.ClientBeginDeleteOptions{CacheControl: to.StringPtr("<cache-control>")})
	if err != nil {
		log.Fatal(err)
	}
	_, err = poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}

// x-ms-original-file: specification/managementgroups/resource-manager/Microsoft.Management/stable/2021-04-01/examples/GetDescendants.json
func ExampleClient_GetDescendants() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armmanagementgroups.NewClient(cred, nil)
	pager := client.GetDescendants("<group-id>",
		&armmanagementgroups.ClientGetDescendantsOptions{Skiptoken: nil,
			Top: nil,
		})
	for {
		nextResult := pager.NextPage(ctx)
		if err := pager.Err(); err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		if !nextResult {
			break
		}
		for _, v := range pager.PageResponse().Value {
			log.Printf("Pager result: %#v\n", v)
		}
	}
}
