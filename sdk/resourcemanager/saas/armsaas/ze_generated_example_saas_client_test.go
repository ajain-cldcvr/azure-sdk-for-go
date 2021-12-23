//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armsaas_test

import (
	"context"
	"log"

	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/saas/armsaas"
)

// x-ms-original-file: specification/saas/resource-manager/Microsoft.SaaS/preview/2018-03-01-beta/examples/saasV2/SaasDelete.json
func ExampleSaaSClient_BeginDelete() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armsaas.NewSaaSClient(cred, nil)
	poller, err := client.BeginDelete(ctx,
		"<resource-id>",
		armsaas.DeleteOptions{
			Feedback:        to.StringPtr("<feedback>"),
			ReasonCode:      to.Float32Ptr(0),
			UnsubscribeOnly: to.BoolPtr(true),
		},
		nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}

// x-ms-original-file: specification/saas/resource-manager/Microsoft.SaaS/preview/2018-03-01-beta/examples/saasV2/SaasGet.json
func ExampleSaaSClient_GetResource() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armsaas.NewSaaSClient(cred, nil)
	res, err := client.GetResource(ctx,
		"<resource-id>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("SaasResource.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/saas/resource-manager/Microsoft.SaaS/preview/2018-03-01-beta/examples/saasV2/SaasPatch.json
func ExampleSaaSClient_BeginUpdateResource() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armsaas.NewSaaSClient(cred, nil)
	poller, err := client.BeginUpdateResource(ctx,
		"<resource-id>",
		armsaas.SaasResourceCreation{
			Properties: &armsaas.SaasCreationProperties{
				SKUID: to.StringPtr("<skuid>"),
			},
			Tags: map[string]*string{},
		},
		nil)
	if err != nil {
		log.Fatal(err)
	}
	res, err := poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("SaasResource.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/saas/resource-manager/Microsoft.SaaS/preview/2018-03-01-beta/examples/saasV2/SaasPut.json
func ExampleSaaSClient_BeginCreateResource() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armsaas.NewSaaSClient(cred, nil)
	poller, err := client.BeginCreateResource(ctx,
		armsaas.SaasResourceCreation{
			Properties: &armsaas.SaasCreationProperties{
				OfferID: to.StringPtr("<offer-id>"),
				PaymentChannelMetadata: map[string]*string{
					"AzureSubscriptionId": to.StringPtr("155af98a-3205-47e7-883b-a2ab9db9f88d"),
				},
				PaymentChannelType: armsaas.PaymentChannelTypeSubscriptionDelegated.ToPtr(),
				PublisherID:        to.StringPtr("<publisher-id>"),
				SaasResourceName:   to.StringPtr("<saas-resource-name>"),
				SKUID:              to.StringPtr("<skuid>"),
				TermID:             to.StringPtr("<term-id>"),
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
	log.Printf("SaasResource.ID: %s\n", *res.ID)
}