//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armrecoveryservicesbackup_test

import (
	"context"
	"log"

	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservicesbackup"
)

// x-ms-original-file: specification/recoveryservicesbackup/resource-manager/Microsoft.RecoveryServices/stable/2021-12-01/examples/AzureIaasVm/V2Policy/v2-Get-Policy.json
func ExampleProtectionPoliciesClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicesbackup.NewProtectionPoliciesClient("<subscription-id>", cred, nil)
	res, err := client.Get(ctx,
		"<vault-name>",
		"<resource-group-name>",
		"<policy-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.ProtectionPoliciesClientGetResult)
}

// x-ms-original-file: specification/recoveryservicesbackup/resource-manager/Microsoft.RecoveryServices/stable/2021-12-01/examples/AzureStorage/ProtectionPolicies_CreateOrUpdate_Daily.json
func ExampleProtectionPoliciesClient_CreateOrUpdate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicesbackup.NewProtectionPoliciesClient("<subscription-id>", cred, nil)
	res, err := client.CreateOrUpdate(ctx,
		"<vault-name>",
		"<resource-group-name>",
		"<policy-name>",
		armrecoveryservicesbackup.ProtectionPolicyResource{
			Properties: &armrecoveryservicesbackup.AzureFileShareProtectionPolicy{
				BackupManagementType: to.StringPtr("<backup-management-type>"),
				RetentionPolicy: &armrecoveryservicesbackup.LongTermRetentionPolicy{
					RetentionPolicyType: to.StringPtr("<retention-policy-type>"),
					DailySchedule: &armrecoveryservicesbackup.DailyRetentionSchedule{
						RetentionDuration: &armrecoveryservicesbackup.RetentionDuration{
							Count:        to.Int32Ptr(5),
							DurationType: armrecoveryservicesbackup.RetentionDurationType("Days").ToPtr(),
						},
						RetentionTimes: []*time.Time{
							to.TimePtr(func() time.Time { t, _ := time.Parse(time.RFC3339Nano, "2021-09-29T08:00:00.000Z"); return t }())},
					},
					MonthlySchedule: &armrecoveryservicesbackup.MonthlyRetentionSchedule{
						RetentionDuration: &armrecoveryservicesbackup.RetentionDuration{
							Count:        to.Int32Ptr(60),
							DurationType: armrecoveryservicesbackup.RetentionDurationType("Months").ToPtr(),
						},
						RetentionScheduleFormatType: armrecoveryservicesbackup.RetentionScheduleFormat("Weekly").ToPtr(),
						RetentionScheduleWeekly: &armrecoveryservicesbackup.WeeklyRetentionFormat{
							DaysOfTheWeek: []*armrecoveryservicesbackup.DayOfWeek{
								armrecoveryservicesbackup.DayOfWeekSunday.ToPtr()},
							WeeksOfTheMonth: []*armrecoveryservicesbackup.WeekOfMonth{
								armrecoveryservicesbackup.WeekOfMonthFirst.ToPtr()},
						},
						RetentionTimes: []*time.Time{
							to.TimePtr(func() time.Time { t, _ := time.Parse(time.RFC3339Nano, "2021-09-29T08:00:00.000Z"); return t }())},
					},
					WeeklySchedule: &armrecoveryservicesbackup.WeeklyRetentionSchedule{
						DaysOfTheWeek: []*armrecoveryservicesbackup.DayOfWeek{
							armrecoveryservicesbackup.DayOfWeekSunday.ToPtr()},
						RetentionDuration: &armrecoveryservicesbackup.RetentionDuration{
							Count:        to.Int32Ptr(12),
							DurationType: armrecoveryservicesbackup.RetentionDurationType("Weeks").ToPtr(),
						},
						RetentionTimes: []*time.Time{
							to.TimePtr(func() time.Time { t, _ := time.Parse(time.RFC3339Nano, "2021-09-29T08:00:00.000Z"); return t }())},
					},
					YearlySchedule: &armrecoveryservicesbackup.YearlyRetentionSchedule{
						MonthsOfYear: []*armrecoveryservicesbackup.MonthOfYear{
							armrecoveryservicesbackup.MonthOfYearJanuary.ToPtr()},
						RetentionDuration: &armrecoveryservicesbackup.RetentionDuration{
							Count:        to.Int32Ptr(10),
							DurationType: armrecoveryservicesbackup.RetentionDurationType("Years").ToPtr(),
						},
						RetentionScheduleFormatType: armrecoveryservicesbackup.RetentionScheduleFormat("Weekly").ToPtr(),
						RetentionScheduleWeekly: &armrecoveryservicesbackup.WeeklyRetentionFormat{
							DaysOfTheWeek: []*armrecoveryservicesbackup.DayOfWeek{
								armrecoveryservicesbackup.DayOfWeekSunday.ToPtr()},
							WeeksOfTheMonth: []*armrecoveryservicesbackup.WeekOfMonth{
								armrecoveryservicesbackup.WeekOfMonthFirst.ToPtr()},
						},
						RetentionTimes: []*time.Time{
							to.TimePtr(func() time.Time { t, _ := time.Parse(time.RFC3339Nano, "2021-09-29T08:00:00.000Z"); return t }())},
					},
				},
				SchedulePolicy: &armrecoveryservicesbackup.SimpleSchedulePolicy{
					SchedulePolicyType:   to.StringPtr("<schedule-policy-type>"),
					ScheduleRunFrequency: armrecoveryservicesbackup.ScheduleRunType("Daily").ToPtr(),
					ScheduleRunTimes: []*time.Time{
						to.TimePtr(func() time.Time { t, _ := time.Parse(time.RFC3339Nano, "2021-09-29T08:00:00.000Z"); return t }())},
				},
				TimeZone:     to.StringPtr("<time-zone>"),
				WorkLoadType: armrecoveryservicesbackup.WorkloadType("AzureFileShare").ToPtr(),
			},
		},
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Response result: %#v\n", res.ProtectionPoliciesClientCreateOrUpdateResult)
}

// x-ms-original-file: specification/recoveryservicesbackup/resource-manager/Microsoft.RecoveryServices/stable/2021-12-01/examples/AzureIaasVm/ProtectionPolicies_Delete.json
func ExampleProtectionPoliciesClient_BeginDelete() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicesbackup.NewProtectionPoliciesClient("<subscription-id>", cred, nil)
	poller, err := client.BeginDelete(ctx,
		"<vault-name>",
		"<resource-group-name>",
		"<policy-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}
