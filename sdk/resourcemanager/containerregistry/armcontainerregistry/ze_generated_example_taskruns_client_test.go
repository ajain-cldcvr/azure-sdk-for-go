//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armcontainerregistry_test

import (
	"context"
	"log"

	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
)

// x-ms-original-file: specification/containerregistry/resource-manager/Microsoft.ContainerRegistry/preview/2019-06-01-preview/examples/TaskRunsGet.json
func ExampleTaskRunsClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armcontainerregistry.NewTaskRunsClient("<subscription-id>", cred, nil)
	res, err := client.Get(ctx,
		"<resource-group-name>",
		"<registry-name>",
		"<task-run-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.TaskRunsClientGetResult)
}

// x-ms-original-file: specification/containerregistry/resource-manager/Microsoft.ContainerRegistry/preview/2019-06-01-preview/examples/TaskRunsCreate.json
func ExampleTaskRunsClient_BeginCreate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armcontainerregistry.NewTaskRunsClient("<subscription-id>", cred, nil)
	poller, err := client.BeginCreate(ctx,
		"<resource-group-name>",
		"<registry-name>",
		"<task-run-name>",
		armcontainerregistry.TaskRun{
			Properties: &armcontainerregistry.TaskRunProperties{
				ForceUpdateTag: to.StringPtr("<force-update-tag>"),
				RunRequest: &armcontainerregistry.EncodedTaskRunRequest{
					Type:                 to.StringPtr("<type>"),
					Credentials:          &armcontainerregistry.Credentials{},
					EncodedTaskContent:   to.StringPtr("<encoded-task-content>"),
					EncodedValuesContent: to.StringPtr("<encoded-values-content>"),
					Platform: &armcontainerregistry.PlatformProperties{
						Architecture: armcontainerregistry.Architecture("amd64").ToPtr(),
						OS:           armcontainerregistry.OS("Linux").ToPtr(),
					},
					Values: []*armcontainerregistry.SetValue{},
				},
			},
		},
		nil)
	if err != nil {
		log.Fatal(err)
	}
	res, err := poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.TaskRunsClientCreateResult)
}

// x-ms-original-file: specification/containerregistry/resource-manager/Microsoft.ContainerRegistry/preview/2019-06-01-preview/examples/TaskRunsDelete.json
func ExampleTaskRunsClient_BeginDelete() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armcontainerregistry.NewTaskRunsClient("<subscription-id>", cred, nil)
	poller, err := client.BeginDelete(ctx,
		"<resource-group-name>",
		"<registry-name>",
		"<task-run-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}

// x-ms-original-file: specification/containerregistry/resource-manager/Microsoft.ContainerRegistry/preview/2019-06-01-preview/examples/TaskRunsUpdate.json
func ExampleTaskRunsClient_BeginUpdate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armcontainerregistry.NewTaskRunsClient("<subscription-id>", cred, nil)
	poller, err := client.BeginUpdate(ctx,
		"<resource-group-name>",
		"<registry-name>",
		"<task-run-name>",
		armcontainerregistry.TaskRunUpdateParameters{
			Properties: &armcontainerregistry.TaskRunPropertiesUpdateParameters{
				ForceUpdateTag: to.StringPtr("<force-update-tag>"),
				RunRequest: &armcontainerregistry.EncodedTaskRunRequest{
					Type:                 to.StringPtr("<type>"),
					IsArchiveEnabled:     to.BoolPtr(true),
					Credentials:          &armcontainerregistry.Credentials{},
					EncodedTaskContent:   to.StringPtr("<encoded-task-content>"),
					EncodedValuesContent: to.StringPtr("<encoded-values-content>"),
					Platform: &armcontainerregistry.PlatformProperties{
						Architecture: armcontainerregistry.Architecture("amd64").ToPtr(),
						OS:           armcontainerregistry.OS("Linux").ToPtr(),
					},
					Values: []*armcontainerregistry.SetValue{},
				},
			},
		},
		nil)
	if err != nil {
		log.Fatal(err)
	}
	res, err := poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.TaskRunsClientUpdateResult)
}

// x-ms-original-file: specification/containerregistry/resource-manager/Microsoft.ContainerRegistry/preview/2019-06-01-preview/examples/TaskRunsGetDetails.json
func ExampleTaskRunsClient_GetDetails() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armcontainerregistry.NewTaskRunsClient("<subscription-id>", cred, nil)
	res, err := client.GetDetails(ctx,
		"<resource-group-name>",
		"<registry-name>",
		"<task-run-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.TaskRunsClientGetDetailsResult)
}

// x-ms-original-file: specification/containerregistry/resource-manager/Microsoft.ContainerRegistry/preview/2019-06-01-preview/examples/TaskRunsList.json
func ExampleTaskRunsClient_List() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armcontainerregistry.NewTaskRunsClient("<subscription-id>", cred, nil)
	pager := client.List("<resource-group-name>",
		"<registry-name>",
		nil)
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
