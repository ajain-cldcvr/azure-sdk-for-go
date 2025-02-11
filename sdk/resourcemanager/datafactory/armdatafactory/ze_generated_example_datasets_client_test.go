//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armdatafactory_test

import (
	"context"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
)

// x-ms-original-file: specification/datafactory/resource-manager/Microsoft.DataFactory/stable/2018-06-01/examples/Datasets_ListByFactory.json
func ExampleDatasetsClient_ListByFactory() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armdatafactory.NewDatasetsClient("<subscription-id>", cred, nil)
	pager := client.ListByFactory("<resource-group-name>",
		"<factory-name>",
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

// x-ms-original-file: specification/datafactory/resource-manager/Microsoft.DataFactory/stable/2018-06-01/examples/Datasets_Create.json
func ExampleDatasetsClient_CreateOrUpdate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armdatafactory.NewDatasetsClient("<subscription-id>", cred, nil)
	res, err := client.CreateOrUpdate(ctx,
		"<resource-group-name>",
		"<factory-name>",
		"<dataset-name>",
		armdatafactory.DatasetResource{
			Properties: &armdatafactory.AzureBlobDataset{
				Type: to.StringPtr("<type>"),
				LinkedServiceName: &armdatafactory.LinkedServiceReference{
					Type:          armdatafactory.LinkedServiceReferenceType("LinkedServiceReference").ToPtr(),
					ReferenceName: to.StringPtr("<reference-name>"),
				},
				Parameters: map[string]*armdatafactory.ParameterSpecification{
					"MyFileName": {
						Type: armdatafactory.ParameterType("String").ToPtr(),
					},
					"MyFolderPath": {
						Type: armdatafactory.ParameterType("String").ToPtr(),
					},
				},
				TypeProperties: &armdatafactory.AzureBlobDatasetTypeProperties{
					Format: &armdatafactory.TextFormat{
						Type: to.StringPtr("<type>"),
					},
					FileName: map[string]interface{}{
						"type":  "Expression",
						"value": "@dataset().MyFileName",
					},
					FolderPath: map[string]interface{}{
						"type":  "Expression",
						"value": "@dataset().MyFolderPath",
					},
				},
			},
		},
		&armdatafactory.DatasetsClientCreateOrUpdateOptions{IfMatch: nil})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.DatasetsClientCreateOrUpdateResult)
}

// x-ms-original-file: specification/datafactory/resource-manager/Microsoft.DataFactory/stable/2018-06-01/examples/Datasets_Get.json
func ExampleDatasetsClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armdatafactory.NewDatasetsClient("<subscription-id>", cred, nil)
	res, err := client.Get(ctx,
		"<resource-group-name>",
		"<factory-name>",
		"<dataset-name>",
		&armdatafactory.DatasetsClientGetOptions{IfNoneMatch: nil})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.DatasetsClientGetResult)
}

// x-ms-original-file: specification/datafactory/resource-manager/Microsoft.DataFactory/stable/2018-06-01/examples/Datasets_Delete.json
func ExampleDatasetsClient_Delete() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armdatafactory.NewDatasetsClient("<subscription-id>", cred, nil)
	_, err = client.Delete(ctx,
		"<resource-group-name>",
		"<factory-name>",
		"<dataset-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
}
