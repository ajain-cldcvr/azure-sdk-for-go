//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armpolicyinsights_test

import (
	"context"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/policyinsights/armpolicyinsights"
)

// x-ms-original-file: specification/policyinsights/resource-manager/Microsoft.PolicyInsights/stable/2020-07-01/examples/PolicyRestrictions_CheckAtSubscriptionScope.json
func ExamplePolicyRestrictionsClient_CheckAtSubscriptionScope() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armpolicyinsights.NewPolicyRestrictionsClient("<subscription-id>", cred, nil)
	res, err := client.CheckAtSubscriptionScope(ctx,
		armpolicyinsights.CheckRestrictionsRequest{
			PendingFields: []*armpolicyinsights.PendingField{
				{
					Field: to.StringPtr("<field>"),
					Values: []*string{
						to.StringPtr("myVMName")},
				},
				{
					Field: to.StringPtr("<field>"),
					Values: []*string{
						to.StringPtr("eastus"),
						to.StringPtr("westus"),
						to.StringPtr("westus2"),
						to.StringPtr("westeurope")},
				},
				{
					Field: to.StringPtr("<field>"),
				}},
			ResourceDetails: &armpolicyinsights.CheckRestrictionsResourceDetails{
				APIVersion: to.StringPtr("<apiversion>"),
				ResourceContent: map[string]interface{}{
					"type": "Microsoft.Compute/virtualMachines",
					"properties": map[string]interface{}{
						"priority": "Spot",
					},
				},
			},
		},
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.PolicyRestrictionsClientCheckAtSubscriptionScopeResult)
}

// x-ms-original-file: specification/policyinsights/resource-manager/Microsoft.PolicyInsights/stable/2020-07-01/examples/PolicyRestrictions_CheckAtResourceGroupScope.json
func ExamplePolicyRestrictionsClient_CheckAtResourceGroupScope() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armpolicyinsights.NewPolicyRestrictionsClient("<subscription-id>", cred, nil)
	res, err := client.CheckAtResourceGroupScope(ctx,
		"<resource-group-name>",
		armpolicyinsights.CheckRestrictionsRequest{
			PendingFields: []*armpolicyinsights.PendingField{
				{
					Field: to.StringPtr("<field>"),
					Values: []*string{
						to.StringPtr("myVMName")},
				},
				{
					Field: to.StringPtr("<field>"),
					Values: []*string{
						to.StringPtr("eastus"),
						to.StringPtr("westus"),
						to.StringPtr("westus2"),
						to.StringPtr("westeurope")},
				},
				{
					Field: to.StringPtr("<field>"),
				}},
			ResourceDetails: &armpolicyinsights.CheckRestrictionsResourceDetails{
				APIVersion: to.StringPtr("<apiversion>"),
				ResourceContent: map[string]interface{}{
					"type": "Microsoft.Compute/virtualMachines",
					"properties": map[string]interface{}{
						"priority": "Spot",
					},
				},
			},
		},
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.PolicyRestrictionsClientCheckAtResourceGroupScopeResult)
}
