
Generated from https://github.com/Azure/azure-rest-api-specs/tree/b97299c968df5f99b724bd1231fd2161731d3b8f

Code generator C:\Users\dapzhang\Documents\workspace\autorest.go

## Breaking Changes

- Const `RuleTypeThresholdCustomAlertRule` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeConnectionToIPNotAllowed` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeMqttC2DRejectedMessagesNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeTimeWindowCustomAlertRule` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeProcessNotAllowed` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeHTTPC2DRejectedMessagesNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeMqttD2CMessagesNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeDenylistCustomAlertRule` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeMqttC2DMessagesNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeFileUploadsNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeDirectMethodInvokesNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeActiveConnectionsNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeLocalUserNotAllowed` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeAllowlistCustomAlertRule` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeAmqpC2DMessagesNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeQueuePurgesNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeFailedLocalLoginsNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeUnauthorizedOperationsNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeAmqpC2DRejectedMessagesNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeAmqpD2CMessagesNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeHTTPC2DMessagesNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeListCustomAlertRule` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeTwinUpdatesNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeCustomAlertRule` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Const `RuleTypeHTTPD2CMessagesNotInAllowedRange` type has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Function `NewContactListPage` signature has been changed from `(func(context.Context, ContactList) (ContactList, error))` to `(ContactList,func(context.Context, ContactList) (ContactList, error))`
- Function `NewExternalSecuritySolutionListPage` signature has been changed from `(func(context.Context, ExternalSecuritySolutionList) (ExternalSecuritySolutionList, error))` to `(ExternalSecuritySolutionList,func(context.Context, ExternalSecuritySolutionList) (ExternalSecuritySolutionList, error))`
- Function `NewAlertsSuppressionRulesListPage` signature has been changed from `(func(context.Context, AlertsSuppressionRulesList) (AlertsSuppressionRulesList, error))` to `(AlertsSuppressionRulesList,func(context.Context, AlertsSuppressionRulesList) (AlertsSuppressionRulesList, error))`
- Function `NewComplianceListPage` signature has been changed from `(func(context.Context, ComplianceList) (ComplianceList, error))` to `(ComplianceList,func(context.Context, ComplianceList) (ComplianceList, error))`
- Function `NewSecureScoreControlDefinitionListPage` signature has been changed from `(func(context.Context, SecureScoreControlDefinitionList) (SecureScoreControlDefinitionList, error))` to `(SecureScoreControlDefinitionList,func(context.Context, SecureScoreControlDefinitionList) (SecureScoreControlDefinitionList, error))`
- Function `NewAutoProvisioningSettingListPage` signature has been changed from `(func(context.Context, AutoProvisioningSettingList) (AutoProvisioningSettingList, error))` to `(AutoProvisioningSettingList,func(context.Context, AutoProvisioningSettingList) (AutoProvisioningSettingList, error))`
- Function `NewOperationListPage` signature has been changed from `(func(context.Context, OperationList) (OperationList, error))` to `(OperationList,func(context.Context, OperationList) (OperationList, error))`
- Function `NewJitNetworkAccessPoliciesListPage` signature has been changed from `(func(context.Context, JitNetworkAccessPoliciesList) (JitNetworkAccessPoliciesList, error))` to `(JitNetworkAccessPoliciesList,func(context.Context, JitNetworkAccessPoliciesList) (JitNetworkAccessPoliciesList, error))`
- Function `NewInformationProtectionPolicyListPage` signature has been changed from `(func(context.Context, InformationProtectionPolicyList) (InformationProtectionPolicyList, error))` to `(InformationProtectionPolicyList,func(context.Context, InformationProtectionPolicyList) (InformationProtectionPolicyList, error))`
- Function `NewTaskListPage` signature has been changed from `(func(context.Context, TaskList) (TaskList, error))` to `(TaskList,func(context.Context, TaskList) (TaskList, error))`
- Function `NewSettingsListPage` signature has been changed from `(func(context.Context, SettingsList) (SettingsList, error))` to `(SettingsList,func(context.Context, SettingsList) (SettingsList, error))`
- Function `NewIoTSecurityAggregatedAlertListPage` signature has been changed from `(func(context.Context, IoTSecurityAggregatedAlertList) (IoTSecurityAggregatedAlertList, error))` to `(IoTSecurityAggregatedAlertList,func(context.Context, IoTSecurityAggregatedAlertList) (IoTSecurityAggregatedAlertList, error))`
- Function `NewAutomationListPage` signature has been changed from `(func(context.Context, AutomationList) (AutomationList, error))` to `(AutomationList,func(context.Context, AutomationList) (AutomationList, error))`
- Function `NewSecureScoreControlListPage` signature has been changed from `(func(context.Context, SecureScoreControlList) (SecureScoreControlList, error))` to `(SecureScoreControlList,func(context.Context, SecureScoreControlList) (SecureScoreControlList, error))`
- Function `NewSubAssessmentListPage` signature has been changed from `(func(context.Context, SubAssessmentList) (SubAssessmentList, error))` to `(SubAssessmentList,func(context.Context, SubAssessmentList) (SubAssessmentList, error))`
- Function `NewRegulatoryComplianceAssessmentListPage` signature has been changed from `(func(context.Context, RegulatoryComplianceAssessmentList) (RegulatoryComplianceAssessmentList, error))` to `(RegulatoryComplianceAssessmentList,func(context.Context, RegulatoryComplianceAssessmentList) (RegulatoryComplianceAssessmentList, error))`
- Function `NewRegulatoryComplianceStandardListPage` signature has been changed from `(func(context.Context, RegulatoryComplianceStandardList) (RegulatoryComplianceStandardList, error))` to `(RegulatoryComplianceStandardList,func(context.Context, RegulatoryComplianceStandardList) (RegulatoryComplianceStandardList, error))`
- Function `NewAllowedConnectionsListPage` signature has been changed from `(func(context.Context, AllowedConnectionsList) (AllowedConnectionsList, error))` to `(AllowedConnectionsList,func(context.Context, AllowedConnectionsList) (AllowedConnectionsList, error))`
- Function `NewTopologyListPage` signature has been changed from `(func(context.Context, TopologyList) (TopologyList, error))` to `(TopologyList,func(context.Context, TopologyList) (TopologyList, error))`
- Function `NewIoTSecuritySolutionsListPage` signature has been changed from `(func(context.Context, IoTSecuritySolutionsList) (IoTSecuritySolutionsList, error))` to `(IoTSecuritySolutionsList,func(context.Context, IoTSecuritySolutionsList) (IoTSecuritySolutionsList, error))`
- Function `NewRegulatoryComplianceControlListPage` signature has been changed from `(func(context.Context, RegulatoryComplianceControlList) (RegulatoryComplianceControlList, error))` to `(RegulatoryComplianceControlList,func(context.Context, RegulatoryComplianceControlList) (RegulatoryComplianceControlList, error))`
- Function `NewDiscoveredSecuritySolutionListPage` signature has been changed from `(func(context.Context, DiscoveredSecuritySolutionList) (DiscoveredSecuritySolutionList, error))` to `(DiscoveredSecuritySolutionList,func(context.Context, DiscoveredSecuritySolutionList) (DiscoveredSecuritySolutionList, error))`
- Function `NewAdaptiveNetworkHardeningsListPage` signature has been changed from `(func(context.Context, AdaptiveNetworkHardeningsList) (AdaptiveNetworkHardeningsList, error))` to `(AdaptiveNetworkHardeningsList,func(context.Context, AdaptiveNetworkHardeningsList) (AdaptiveNetworkHardeningsList, error))`
- Function `NewAlertListPage` signature has been changed from `(func(context.Context, AlertList) (AlertList, error))` to `(AlertList,func(context.Context, AlertList) (AlertList, error))`
- Function `NewWorkspaceSettingListPage` signature has been changed from `(func(context.Context, WorkspaceSettingList) (WorkspaceSettingList, error))` to `(WorkspaceSettingList,func(context.Context, WorkspaceSettingList) (WorkspaceSettingList, error))`
- Function `NewIoTSecurityAggregatedRecommendationListPage` signature has been changed from `(func(context.Context, IoTSecurityAggregatedRecommendationList) (IoTSecurityAggregatedRecommendationList, error))` to `(IoTSecurityAggregatedRecommendationList,func(context.Context, IoTSecurityAggregatedRecommendationList) (IoTSecurityAggregatedRecommendationList, error))`
- Function `NewSecureScoresListPage` signature has been changed from `(func(context.Context, SecureScoresList) (SecureScoresList, error))` to `(SecureScoresList,func(context.Context, SecureScoresList) (SecureScoresList, error))`
- Function `NewAscLocationListPage` signature has been changed from `(func(context.Context, AscLocationList) (AscLocationList, error))` to `(AscLocationList,func(context.Context, AscLocationList) (AscLocationList, error))`
- Function `NewDeviceSecurityGroupListPage` signature has been changed from `(func(context.Context, DeviceSecurityGroupList) (DeviceSecurityGroupList, error))` to `(DeviceSecurityGroupList,func(context.Context, DeviceSecurityGroupList) (DeviceSecurityGroupList, error))`
- Function `NewConnectorSettingListPage` signature has been changed from `(func(context.Context, ConnectorSettingList) (ConnectorSettingList, error))` to `(ConnectorSettingList,func(context.Context, ConnectorSettingList) (ConnectorSettingList, error))`
- Type of `FileUploadsNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `AllowlistCustomAlertRule.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `AmqpC2DMessagesNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `DirectMethodInvokesNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `CustomAlertRule.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `TwinUpdatesNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `ConnectionToIPNotAllowed.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `LocalUserNotAllowed.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `MqttD2CMessagesNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `HTTPC2DMessagesNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `ThresholdCustomAlertRule.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `TimeWindowCustomAlertRule.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `MqttC2DMessagesNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `ActiveConnectionsNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `HTTPC2DRejectedMessagesNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `DenylistCustomAlertRule.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `QueuePurgesNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `FailedLocalLoginsNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `ProcessNotAllowed.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `AmqpC2DRejectedMessagesNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `MqttC2DRejectedMessagesNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `UnauthorizedOperationsNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `ListCustomAlertRule.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `HTTPD2CMessagesNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`
- Type of `AmqpD2CMessagesNotInAllowedRange.RuleType` has been changed from `RuleType` to `RuleTypeBasicCustomAlertRule`

## New Content

- Const `Recurring` is added
- Const `ScanStateFailedToRun` is added
- Const `ScanStateFailed` is added
- Const `RuleSeverityLow` is added
- Const `NegativeList` is added
- Const `BaselineExpected` is added
- Const `Binary` is added
- Const `OnDemand` is added
- Const `ScanStateInProgress` is added
- Const `SecureScoreControls` is added
- Const `NonFinding` is added
- Const `Finding` is added
- Const `RuleSeverityMedium` is added
- Const `InternalError` is added
- Const `SecureScores` is added
- Const `ScanStatePassed` is added
- Const `RuleSeverityHigh` is added
- Const `RuleSeverityInformational` is added
- Const `RuleSeverityObsolete` is added
- Const `PositiveList` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.CreateOrUpdateResponder(*http.Response) (RuleResults,error)` is added
- Function `SQLVulnerabilityAssessmentScansClient.GetPreparer(context.Context,string,string,string,string) (*http.Request,error)` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.CreateOrUpdate(context.Context,string,string,string,string,*RuleResultsInput) (RuleResults,error)` is added
- Function `SQLVulnerabilityAssessmentScanResultsClient.ListResponder(*http.Response) (ScanResults,error)` is added
- Function `SQLVulnerabilityAssessmentScansClient.ListPreparer(context.Context,string,string,string) (*http.Request,error)` is added
- Function `SQLVulnerabilityAssessmentScanResultsClient.List(context.Context,string,string,string,string) (ScanResults,error)` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.GetSender(*http.Request) (*http.Response,error)` is added
- Function `PossibleRuleSeverityValues() []RuleSeverity` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.ListSender(*http.Request) (*http.Response,error)` is added
- Function `RuleResults.MarshalJSON() ([]byte,error)` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.AddSender(*http.Request) (*http.Response,error)` is added
- Function `ScanResult.MarshalJSON() ([]byte,error)` is added
- Function `NewSQLVulnerabilityAssessmentScansClient(string,string) SQLVulnerabilityAssessmentScansClient` is added
- Function `SQLVulnerabilityAssessmentScanResultsClient.GetPreparer(context.Context,string,string,string,string,string) (*http.Request,error)` is added
- Function `SQLVulnerabilityAssessmentScansClient.Get(context.Context,string,string,string,string) (Scan,error)` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.DeletePreparer(context.Context,string,string,string,string) (*http.Request,error)` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.CreateOrUpdatePreparer(context.Context,string,string,string,string,*RuleResultsInput) (*http.Request,error)` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.DeleteResponder(*http.Response) (autorest.Response,error)` is added
- Function `RulesResultsInput.MarshalJSON() ([]byte,error)` is added
- Function `SQLVulnerabilityAssessmentScansClient.ListResponder(*http.Response) (Scans,error)` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.Add(context.Context,string,string,string,*RulesResultsInput) (RulesResults,error)` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.Delete(context.Context,string,string,string,string) (autorest.Response,error)` is added
- Function `Scan.MarshalJSON() ([]byte,error)` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.DeleteSender(*http.Request) (*http.Response,error)` is added
- Function `NewSQLVulnerabilityAssessmentBaselineRulesClient(string,string) SQLVulnerabilityAssessmentBaselineRulesClient` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.AddPreparer(context.Context,string,string,string,*RulesResultsInput) (*http.Request,error)` is added
- Function `NewSQLVulnerabilityAssessmentBaselineRulesClientWithBaseURI(string,string,string) SQLVulnerabilityAssessmentBaselineRulesClient` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.Get(context.Context,string,string,string,string) (RuleResults,error)` is added
- Function `SQLVulnerabilityAssessmentScanResultsClient.ListPreparer(context.Context,string,string,string,string) (*http.Request,error)` is added
- Function `PossibleRuleTypeBasicCustomAlertRuleValues() []RuleTypeBasicCustomAlertRule` is added
- Function `NewSQLVulnerabilityAssessmentScanResultsClient(string,string) SQLVulnerabilityAssessmentScanResultsClient` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.AddResponder(*http.Response) (RulesResults,error)` is added
- Function `SQLVulnerabilityAssessmentScanResultsClient.Get(context.Context,string,string,string,string,string) (ScanResult,error)` is added
- Function `SQLVulnerabilityAssessmentScansClient.ListSender(*http.Request) (*http.Response,error)` is added
- Function `NewSQLVulnerabilityAssessmentScanResultsClientWithBaseURI(string,string,string) SQLVulnerabilityAssessmentScanResultsClient` is added
- Function `PossibleScanStateValues() []ScanState` is added
- Function `SQLVulnerabilityAssessmentScanResultsClient.GetResponder(*http.Response) (ScanResult,error)` is added
- Function `SQLVulnerabilityAssessmentScansClient.GetResponder(*http.Response) (Scan,error)` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.ListResponder(*http.Response) (RulesResults,error)` is added
- Function `SQLVulnerabilityAssessmentScanResultsClient.GetSender(*http.Request) (*http.Response,error)` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.List(context.Context,string,string,string) (RulesResults,error)` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.GetResponder(*http.Response) (RuleResults,error)` is added
- Function `SQLVulnerabilityAssessmentScansClient.List(context.Context,string,string,string) (Scans,error)` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.ListPreparer(context.Context,string,string,string) (*http.Request,error)` is added
- Function `PossibleRuleStatusValues() []RuleStatus` is added
- Function `PossibleScanTriggerTypeValues() []ScanTriggerType` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.CreateOrUpdateSender(*http.Request) (*http.Response,error)` is added
- Function `SQLVulnerabilityAssessmentScanResultsClient.ListSender(*http.Request) (*http.Response,error)` is added
- Function `NewSQLVulnerabilityAssessmentScansClientWithBaseURI(string,string,string) SQLVulnerabilityAssessmentScansClient` is added
- Function `SQLVulnerabilityAssessmentBaselineRulesClient.GetPreparer(context.Context,string,string,string,string) (*http.Request,error)` is added
- Function `SQLVulnerabilityAssessmentScansClient.GetSender(*http.Request) (*http.Response,error)` is added
- Struct `Baseline` is added
- Struct `BaselineAdjustedResult` is added
- Struct `BenchmarkReference` is added
- Struct `QueryCheck` is added
- Struct `Remediation` is added
- Struct `RuleResults` is added
- Struct `RuleResultsInput` is added
- Struct `RuleResultsProperties` is added
- Struct `RulesResults` is added
- Struct `RulesResultsInput` is added
- Struct `SQLVulnerabilityAssessmentBaselineRulesClient` is added
- Struct `SQLVulnerabilityAssessmentScanResultsClient` is added
- Struct `SQLVulnerabilityAssessmentScansClient` is added
- Struct `Scan` is added
- Struct `ScanProperties` is added
- Struct `ScanResult` is added
- Struct `ScanResultProperties` is added
- Struct `ScanResults` is added
- Struct `Scans` is added
- Struct `VaRule` is added
