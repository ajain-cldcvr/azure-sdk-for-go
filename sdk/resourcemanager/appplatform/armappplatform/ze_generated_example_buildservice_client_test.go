//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armappplatform_test

import (
	"context"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appplatform/armappplatform"
)

// x-ms-original-file: specification/appplatform/resource-manager/Microsoft.AppPlatform/preview/2022-01-01-preview/examples/BuildService_ListBuildServices.json
func ExampleBuildServiceClient_ListBuildServices() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armappplatform.NewBuildServiceClient("<subscription-id>", cred, nil)
	pager := client.ListBuildServices("<resource-group-name>",
		"<service-name>",
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

// x-ms-original-file: specification/appplatform/resource-manager/Microsoft.AppPlatform/preview/2022-01-01-preview/examples/BuildService_GetBuildService.json
func ExampleBuildServiceClient_GetBuildService() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armappplatform.NewBuildServiceClient("<subscription-id>", cred, nil)
	res, err := client.GetBuildService(ctx,
		"<resource-group-name>",
		"<service-name>",
		"<build-service-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.BuildServiceClientGetBuildServiceResult)
}

// x-ms-original-file: specification/appplatform/resource-manager/Microsoft.AppPlatform/preview/2022-01-01-preview/examples/BuildService_ListBuilds.json
func ExampleBuildServiceClient_ListBuilds() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armappplatform.NewBuildServiceClient("<subscription-id>", cred, nil)
	pager := client.ListBuilds("<resource-group-name>",
		"<service-name>",
		"<build-service-name>",
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

// x-ms-original-file: specification/appplatform/resource-manager/Microsoft.AppPlatform/preview/2022-01-01-preview/examples/BuildService_GetBuild.json
func ExampleBuildServiceClient_GetBuild() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armappplatform.NewBuildServiceClient("<subscription-id>", cred, nil)
	res, err := client.GetBuild(ctx,
		"<resource-group-name>",
		"<service-name>",
		"<build-service-name>",
		"<build-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.BuildServiceClientGetBuildResult)
}

// x-ms-original-file: specification/appplatform/resource-manager/Microsoft.AppPlatform/preview/2022-01-01-preview/examples/BuildService_CreateOrUpdateBuild.json
func ExampleBuildServiceClient_CreateOrUpdateBuild() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armappplatform.NewBuildServiceClient("<subscription-id>", cred, nil)
	res, err := client.CreateOrUpdateBuild(ctx,
		"<resource-group-name>",
		"<service-name>",
		"<build-service-name>",
		"<build-name>",
		armappplatform.Build{
			Properties: &armappplatform.BuildProperties{
				AgentPool: to.StringPtr("<agent-pool>"),
				Builder:   to.StringPtr("<builder>"),
				Env: map[string]*string{
					"environmentVariable": to.StringPtr("test"),
				},
				RelativePath: to.StringPtr("<relative-path>"),
			},
		},
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.BuildServiceClientCreateOrUpdateBuildResult)
}

// x-ms-original-file: specification/appplatform/resource-manager/Microsoft.AppPlatform/preview/2022-01-01-preview/examples/BuildService_ListBuildResults.json
func ExampleBuildServiceClient_ListBuildResults() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armappplatform.NewBuildServiceClient("<subscription-id>", cred, nil)
	pager := client.ListBuildResults("<resource-group-name>",
		"<service-name>",
		"<build-service-name>",
		"<build-name>",
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

// x-ms-original-file: specification/appplatform/resource-manager/Microsoft.AppPlatform/preview/2022-01-01-preview/examples/BuildService_GetBuildResult.json
func ExampleBuildServiceClient_GetBuildResult() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armappplatform.NewBuildServiceClient("<subscription-id>", cred, nil)
	res, err := client.GetBuildResult(ctx,
		"<resource-group-name>",
		"<service-name>",
		"<build-service-name>",
		"<build-name>",
		"<build-result-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.BuildServiceClientGetBuildResultResult)
}

// x-ms-original-file: specification/appplatform/resource-manager/Microsoft.AppPlatform/preview/2022-01-01-preview/examples/BuildService_GetBuildResultLog.json
func ExampleBuildServiceClient_GetBuildResultLog() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armappplatform.NewBuildServiceClient("<subscription-id>", cred, nil)
	res, err := client.GetBuildResultLog(ctx,
		"<resource-group-name>",
		"<service-name>",
		"<build-service-name>",
		"<build-name>",
		"<build-result-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.BuildServiceClientGetBuildResultLogResult)
}

// x-ms-original-file: specification/appplatform/resource-manager/Microsoft.AppPlatform/preview/2022-01-01-preview/examples/BuildService_ListSupportedBuildpacks.json
func ExampleBuildServiceClient_ListSupportedBuildpacks() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armappplatform.NewBuildServiceClient("<subscription-id>", cred, nil)
	res, err := client.ListSupportedBuildpacks(ctx,
		"<resource-group-name>",
		"<service-name>",
		"<build-service-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.BuildServiceClientListSupportedBuildpacksResult)
}

// x-ms-original-file: specification/appplatform/resource-manager/Microsoft.AppPlatform/preview/2022-01-01-preview/examples/BuildService_GetSupportedBuildpack.json
func ExampleBuildServiceClient_GetSupportedBuildpack() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armappplatform.NewBuildServiceClient("<subscription-id>", cred, nil)
	res, err := client.GetSupportedBuildpack(ctx,
		"<resource-group-name>",
		"<service-name>",
		"<build-service-name>",
		"<buildpack-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.BuildServiceClientGetSupportedBuildpackResult)
}

// x-ms-original-file: specification/appplatform/resource-manager/Microsoft.AppPlatform/preview/2022-01-01-preview/examples/BuildService_ListSupportedStacks.json
func ExampleBuildServiceClient_ListSupportedStacks() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armappplatform.NewBuildServiceClient("<subscription-id>", cred, nil)
	res, err := client.ListSupportedStacks(ctx,
		"<resource-group-name>",
		"<service-name>",
		"<build-service-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.BuildServiceClientListSupportedStacksResult)
}

// x-ms-original-file: specification/appplatform/resource-manager/Microsoft.AppPlatform/preview/2022-01-01-preview/examples/BuildService_GetSupportedStack.json
func ExampleBuildServiceClient_GetSupportedStack() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armappplatform.NewBuildServiceClient("<subscription-id>", cred, nil)
	res, err := client.GetSupportedStack(ctx,
		"<resource-group-name>",
		"<service-name>",
		"<build-service-name>",
		"<stack-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.BuildServiceClientGetSupportedStackResult)
}
