//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armsearch

import (
	"encoding/json"
	"reflect"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// AdminKeyResult - Response containing the primary and secondary admin API keys for a given Azure Cognitive Search service.
type AdminKeyResult struct {
	// READ-ONLY; The primary admin API key of the search service.
	PrimaryKey *string `json:"primaryKey,omitempty" azure:"ro"`

	// READ-ONLY; The secondary admin API key of the search service.
	SecondaryKey *string `json:"secondaryKey,omitempty" azure:"ro"`
}

// AdminKeysGetOptions contains the optional parameters for the AdminKeys.Get method.
type AdminKeysGetOptions struct {
	// placeholder for future optional parameters
}

// AdminKeysRegenerateOptions contains the optional parameters for the AdminKeys.Regenerate method.
type AdminKeysRegenerateOptions struct {
	// placeholder for future optional parameters
}

// AsyncOperationResult - The details of a long running asynchronous shared private link resource operation
type AsyncOperationResult struct {
	// The current status of the long running asynchronous shared private link resource operation.
	Status *SharedPrivateLinkResourceAsyncOperationResult `json:"status,omitempty"`
}

// CheckNameAvailabilityInput - Input of check name availability API.
type CheckNameAvailabilityInput struct {
	// REQUIRED; The search service name to validate. Search service names must only contain lowercase letters, digits or dashes, cannot use dash as the first
	// two or last one characters, cannot contain consecutive
	// dashes, and must be between 2 and 60 characters in length.
	Name *string `json:"name,omitempty"`

	// REQUIRED; The type of the resource whose name is to be validated. This value must always be 'searchServices'.
	Type *string `json:"type,omitempty"`
}

// CheckNameAvailabilityOutput - Output of check name availability API.
type CheckNameAvailabilityOutput struct {
	// READ-ONLY; A value indicating whether the name is available.
	IsNameAvailable *bool `json:"nameAvailable,omitempty" azure:"ro"`

	// READ-ONLY; A message that explains why the name is invalid and provides resource naming requirements. Available only if 'Invalid' is returned in the
	// 'reason' property.
	Message *string `json:"message,omitempty" azure:"ro"`

	// READ-ONLY; The reason why the name is not available. 'Invalid' indicates the name provided does not match the naming requirements (incorrect length,
	// unsupported characters, etc.). 'AlreadyExists' indicates that
	// the name is already in use and is therefore unavailable.
	Reason *UnavailableNameReason `json:"reason,omitempty" azure:"ro"`
}

// CloudError - Contains information about an API error.
// Implements the error and azcore.HTTPResponse interfaces.
type CloudError struct {
	raw string
	// Describes a particular API error with an error code and a message.
	InnerError *CloudErrorBody `json:"error,omitempty"`
}

// Error implements the error interface for type CloudError.
// The contents of the error text are not contractual and subject to change.
func (e CloudError) Error() string {
	return e.raw
}

// CloudErrorBody - Describes a particular API error with an error code and a message.
type CloudErrorBody struct {
	// An error code that describes the error condition more precisely than an HTTP status code. Can be used to programmatically handle specific error cases.
	Code *string `json:"code,omitempty"`

	// Contains nested errors that are related to this error.
	Details []*CloudErrorBody `json:"details,omitempty"`

	// A message that describes the error in detail and provides debugging information.
	Message *string `json:"message,omitempty"`

	// The target of the particular error (for example, the name of the property in error).
	Target *string `json:"target,omitempty"`
}

// MarshalJSON implements the json.Marshaller interface for type CloudErrorBody.
func (c CloudErrorBody) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "code", c.Code)
	populate(objectMap, "details", c.Details)
	populate(objectMap, "message", c.Message)
	populate(objectMap, "target", c.Target)
	return json.Marshal(objectMap)
}

// IPRule - The IP restriction rule of the Azure Cognitive Search service.
type IPRule struct {
	// Value corresponding to a single IPv4 address (eg., 123.1.2.3) or an IP range in CIDR format (eg., 123.1.2.3/24) to be allowed.
	Value *string `json:"value,omitempty"`
}

// Identity for the resource.
type Identity struct {
	// REQUIRED; The identity type.
	Type *IdentityType `json:"type,omitempty"`

	// READ-ONLY; The principal ID of resource identity.
	PrincipalID *string `json:"principalId,omitempty" azure:"ro"`

	// READ-ONLY; The tenant ID of resource.
	TenantID *string `json:"tenantId,omitempty" azure:"ro"`
}

// ListQueryKeysResult - Response containing the query API keys for a given Azure Cognitive Search service.
type ListQueryKeysResult struct {
	// READ-ONLY; Request URL that can be used to query next page of query keys. Returned when the total number of requested query keys exceed maximum page
	// size.
	NextLink *string `json:"nextLink,omitempty" azure:"ro"`

	// READ-ONLY; The query keys for the Azure Cognitive Search service.
	Value []*QueryKey `json:"value,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type ListQueryKeysResult.
func (l ListQueryKeysResult) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "nextLink", l.NextLink)
	populate(objectMap, "value", l.Value)
	return json.Marshal(objectMap)
}

// NetworkRuleSet - Network specific rules that determine how the Azure Cognitive Search service may be reached.
type NetworkRuleSet struct {
	// A list of IP restriction rules that defines the inbound network(s) with allowing access to the search service endpoint. At the meantime, all other public
	// IP networks are blocked by the firewall. These
	// restriction rules are applied only when the 'publicNetworkAccess' of the search service is 'enabled'; otherwise, traffic over public interface is not
	// allowed even with any public IP rules, and private
	// endpoint connections would be the exclusive access method.
	IPRules []*IPRule `json:"ipRules,omitempty"`
}

// MarshalJSON implements the json.Marshaller interface for type NetworkRuleSet.
func (n NetworkRuleSet) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "ipRules", n.IPRules)
	return json.Marshal(objectMap)
}

// Operation - Describes a REST API operation.
type Operation struct {
	// READ-ONLY; The object that describes the operation.
	Display *OperationDisplay `json:"display,omitempty" azure:"ro"`

	// READ-ONLY; The name of the operation. This name is of the form {provider}/{resource}/{operation}.
	Name *string `json:"name,omitempty" azure:"ro"`
}

// OperationDisplay - The object that describes the operation.
type OperationDisplay struct {
	// READ-ONLY; The friendly name of the operation.
	Description *string `json:"description,omitempty" azure:"ro"`

	// READ-ONLY; The operation type: read, write, delete, listKeys/action, etc.
	Operation *string `json:"operation,omitempty" azure:"ro"`

	// READ-ONLY; The friendly name of the resource provider.
	Provider *string `json:"provider,omitempty" azure:"ro"`

	// READ-ONLY; The resource type on which the operation is performed.
	Resource *string `json:"resource,omitempty" azure:"ro"`
}

// OperationListResult - The result of the request to list REST API operations. It contains a list of operations and a URL to get the next set of results.
type OperationListResult struct {
	// READ-ONLY; The URL to get the next set of operation list results, if any.
	NextLink *string `json:"nextLink,omitempty" azure:"ro"`

	// READ-ONLY; The list of operations supported by the resource provider.
	Value []*Operation `json:"value,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type OperationListResult.
func (o OperationListResult) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "nextLink", o.NextLink)
	populate(objectMap, "value", o.Value)
	return json.Marshal(objectMap)
}

// OperationsListOptions contains the optional parameters for the Operations.List method.
type OperationsListOptions struct {
	// placeholder for future optional parameters
}

// PrivateEndpointConnection - Describes an existing Private Endpoint connection to the Azure Cognitive Search service.
type PrivateEndpointConnection struct {
	Resource
	// Describes the properties of an existing Private Endpoint connection to the Azure Cognitive Search service.
	Properties *PrivateEndpointConnectionProperties `json:"properties,omitempty"`
}

// MarshalJSON implements the json.Marshaller interface for type PrivateEndpointConnection.
func (p PrivateEndpointConnection) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	p.Resource.marshalInternal(objectMap)
	populate(objectMap, "properties", p.Properties)
	return json.Marshal(objectMap)
}

// PrivateEndpointConnectionListResult - Response containing a list of Private Endpoint connections.
type PrivateEndpointConnectionListResult struct {
	// READ-ONLY; Request URL that can be used to query next page of private endpoint connections. Returned when the total number of requested private endpoint
	// connections exceed maximum page size.
	NextLink *string `json:"nextLink,omitempty" azure:"ro"`

	// READ-ONLY; The list of Private Endpoint connections.
	Value []*PrivateEndpointConnection `json:"value,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type PrivateEndpointConnectionListResult.
func (p PrivateEndpointConnectionListResult) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "nextLink", p.NextLink)
	populate(objectMap, "value", p.Value)
	return json.Marshal(objectMap)
}

// PrivateEndpointConnectionProperties - Describes the properties of an existing Private Endpoint connection to the Azure Cognitive Search service.
type PrivateEndpointConnectionProperties struct {
	// The private endpoint resource from Microsoft.Network provider.
	PrivateEndpoint *PrivateEndpointConnectionPropertiesPrivateEndpoint `json:"privateEndpoint,omitempty"`

	// Describes the current state of an existing Private Link Service connection to the Azure Private Endpoint.
	PrivateLinkServiceConnectionState *PrivateEndpointConnectionPropertiesPrivateLinkServiceConnectionState `json:"privateLinkServiceConnectionState,omitempty"`
}

// PrivateEndpointConnectionPropertiesPrivateEndpoint - The private endpoint resource from Microsoft.Network provider.
type PrivateEndpointConnectionPropertiesPrivateEndpoint struct {
	// The resource id of the private endpoint resource from Microsoft.Network provider.
	ID *string `json:"id,omitempty"`
}

// PrivateEndpointConnectionPropertiesPrivateLinkServiceConnectionState - Describes the current state of an existing Private Link Service connection to
// the Azure Private Endpoint.
type PrivateEndpointConnectionPropertiesPrivateLinkServiceConnectionState struct {
	// A description of any extra actions that may be required.
	ActionsRequired *string `json:"actionsRequired,omitempty"`

	// The description for the private link service connection state.
	Description *string `json:"description,omitempty"`

	// Status of the the private link service connection. Can be Pending, Approved, Rejected, or Disconnected.
	Status *PrivateLinkServiceConnectionStatus `json:"status,omitempty"`
}

// PrivateEndpointConnectionsDeleteOptions contains the optional parameters for the PrivateEndpointConnections.Delete method.
type PrivateEndpointConnectionsDeleteOptions struct {
	// placeholder for future optional parameters
}

// PrivateEndpointConnectionsGetOptions contains the optional parameters for the PrivateEndpointConnections.Get method.
type PrivateEndpointConnectionsGetOptions struct {
	// placeholder for future optional parameters
}

// PrivateEndpointConnectionsListByServiceOptions contains the optional parameters for the PrivateEndpointConnections.ListByService method.
type PrivateEndpointConnectionsListByServiceOptions struct {
	// placeholder for future optional parameters
}

// PrivateEndpointConnectionsUpdateOptions contains the optional parameters for the PrivateEndpointConnections.Update method.
type PrivateEndpointConnectionsUpdateOptions struct {
	// placeholder for future optional parameters
}

// PrivateLinkResource - Describes a supported private link resource for the Azure Cognitive Search service.
type PrivateLinkResource struct {
	Resource
	// READ-ONLY; Describes the properties of a supported private link resource for the Azure Cognitive Search service.
	Properties *PrivateLinkResourceProperties `json:"properties,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type PrivateLinkResource.
func (p PrivateLinkResource) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	p.Resource.marshalInternal(objectMap)
	populate(objectMap, "properties", p.Properties)
	return json.Marshal(objectMap)
}

// PrivateLinkResourceProperties - Describes the properties of a supported private link resource for the Azure Cognitive Search service. For a given API
// version, this represents the 'supported' groupIds when creating a shared private
// link resource.
type PrivateLinkResourceProperties struct {
	// READ-ONLY; The group ID of the private link resource.
	GroupID *string `json:"groupId,omitempty" azure:"ro"`

	// READ-ONLY; The list of required members of the private link resource.
	RequiredMembers []*string `json:"requiredMembers,omitempty" azure:"ro"`

	// READ-ONLY; The list of required DNS zone names of the private link resource.
	RequiredZoneNames []*string `json:"requiredZoneNames,omitempty" azure:"ro"`

	// READ-ONLY; The list of resources that are onboarded to private link service, that are supported by Azure Cognitive Search.
	ShareablePrivateLinkResourceTypes []*ShareablePrivateLinkResourceType `json:"shareablePrivateLinkResourceTypes,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type PrivateLinkResourceProperties.
func (p PrivateLinkResourceProperties) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "groupId", p.GroupID)
	populate(objectMap, "requiredMembers", p.RequiredMembers)
	populate(objectMap, "requiredZoneNames", p.RequiredZoneNames)
	populate(objectMap, "shareablePrivateLinkResourceTypes", p.ShareablePrivateLinkResourceTypes)
	return json.Marshal(objectMap)
}

// PrivateLinkResourcesListSupportedOptions contains the optional parameters for the PrivateLinkResources.ListSupported method.
type PrivateLinkResourcesListSupportedOptions struct {
	// placeholder for future optional parameters
}

// PrivateLinkResourcesResult - Response containing a list of supported Private Link Resources.
type PrivateLinkResourcesResult struct {
	// READ-ONLY; The list of supported Private Link Resources.
	Value []*PrivateLinkResource `json:"value,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type PrivateLinkResourcesResult.
func (p PrivateLinkResourcesResult) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "value", p.Value)
	return json.Marshal(objectMap)
}

// QueryKey - Describes an API key for a given Azure Cognitive Search service that has permissions for query operations only.
type QueryKey struct {
	// READ-ONLY; The value of the query API key.
	Key *string `json:"key,omitempty" azure:"ro"`

	// READ-ONLY; The name of the query API key; may be empty.
	Name *string `json:"name,omitempty" azure:"ro"`
}

// QueryKeysCreateOptions contains the optional parameters for the QueryKeys.Create method.
type QueryKeysCreateOptions struct {
	// placeholder for future optional parameters
}

// QueryKeysDeleteOptions contains the optional parameters for the QueryKeys.Delete method.
type QueryKeysDeleteOptions struct {
	// placeholder for future optional parameters
}

// QueryKeysListBySearchServiceOptions contains the optional parameters for the QueryKeys.ListBySearchService method.
type QueryKeysListBySearchServiceOptions struct {
	// placeholder for future optional parameters
}

// Resource - Common fields that are returned in the response for all Azure Resource Manager resources
type Resource struct {
	// READ-ONLY; Fully qualified resource ID for the resource. Ex - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
	ID *string `json:"id,omitempty" azure:"ro"`

	// READ-ONLY; The name of the resource
	Name *string `json:"name,omitempty" azure:"ro"`

	// READ-ONLY; The type of the resource. E.g. "Microsoft.Compute/virtualMachines" or "Microsoft.Storage/storageAccounts"
	Type *string `json:"type,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type Resource.
func (r Resource) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	r.marshalInternal(objectMap)
	return json.Marshal(objectMap)
}

func (r Resource) marshalInternal(objectMap map[string]interface{}) {
	populate(objectMap, "id", r.ID)
	populate(objectMap, "name", r.Name)
	populate(objectMap, "type", r.Type)
}

// SKU - Defines the SKU of an Azure Cognitive Search Service, which determines price tier and capacity limits.
type SKU struct {
	// The SKU of the search service. Valid values include: 'free': Shared service. 'basic': Dedicated service with up to 3 replicas. 'standard': Dedicated
	// service with up to 12 partitions and 12 replicas.
	// 'standard2': Similar to standard, but with more capacity per search unit. 'standard3': The largest Standard offering with up to 12 partitions and 12
	// replicas (or up to 3 partitions with more indexes
	// if you also set the hostingMode property to 'highDensity'). 'storageoptimizedl1': Supports 1TB per partition, up to 12 partitions. 'storageoptimizedl2':
	// Supports 2TB per partition, up to 12
	// partitions.'
	Name *SKUName `json:"name,omitempty"`
}

// SearchManagementRequestOptions contains a group of parameters for the AdminKeys.Get method.
type SearchManagementRequestOptions struct {
	// A client-generated GUID value that identifies this request. If specified, this will be included in response information as a way to track the request.
	ClientRequestID *string
}

// SearchService - Describes an Azure Cognitive Search service and its current state.
type SearchService struct {
	TrackedResource
	// The identity of the resource.
	Identity *Identity `json:"identity,omitempty"`

	// Properties of the search service.
	Properties *SearchServiceProperties `json:"properties,omitempty"`

	// The SKU of the Search Service, which determines price tier and capacity limits. This property is required when creating a new Search Service.
	SKU *SKU `json:"sku,omitempty"`
}

// MarshalJSON implements the json.Marshaller interface for type SearchService.
func (s SearchService) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	s.TrackedResource.marshalInternal(objectMap)
	populate(objectMap, "identity", s.Identity)
	populate(objectMap, "properties", s.Properties)
	populate(objectMap, "sku", s.SKU)
	return json.Marshal(objectMap)
}

// SearchServiceListResult - Response containing a list of Azure Cognitive Search services.
type SearchServiceListResult struct {
	// READ-ONLY; Request URL that can be used to query next page of search services. Returned when the total number of requested search services exceed maximum
	// page size.
	NextLink *string `json:"nextLink,omitempty" azure:"ro"`

	// READ-ONLY; The list of search services.
	Value []*SearchService `json:"value,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type SearchServiceListResult.
func (s SearchServiceListResult) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "nextLink", s.NextLink)
	populate(objectMap, "value", s.Value)
	return json.Marshal(objectMap)
}

// SearchServiceProperties - Properties of the search service.
type SearchServiceProperties struct {
	// Applicable only for the standard3 SKU. You can set this property to enable up to 3 high density partitions that allow up to 1000 indexes, which is much
	// higher than the maximum indexes allowed for any
	// other SKU. For the standard3 SKU, the value is either 'default' or 'highDensity'. For all other SKUs, this value must be 'default'.
	HostingMode *HostingMode `json:"hostingMode,omitempty"`

	// Network specific rules that determine how the Azure Cognitive Search service may be reached.
	NetworkRuleSet *NetworkRuleSet `json:"networkRuleSet,omitempty"`

	// The number of partitions in the search service; if specified, it can be 1, 2, 3, 4, 6, or 12. Values greater than 1 are only valid for standard SKUs.
	// For 'standard3' services with hostingMode set to
	// 'highDensity', the allowed values are between 1 and 3.
	PartitionCount *int32 `json:"partitionCount,omitempty"`

	// This value can be set to 'enabled' to avoid breaking changes on existing customer resources and templates. If set to 'disabled', traffic over public
	// interface is not allowed, and private endpoint
	// connections would be the exclusive access method.
	PublicNetworkAccess *PublicNetworkAccess `json:"publicNetworkAccess,omitempty"`

	// The number of replicas in the search service. If specified, it must be a value between 1 and 12 inclusive for standard SKUs or between 1 and 3 inclusive
	// for basic SKU.
	ReplicaCount *int32 `json:"replicaCount,omitempty"`

	// READ-ONLY; The list of private endpoint connections to the Azure Cognitive Search service.
	PrivateEndpointConnections []*PrivateEndpointConnection `json:"privateEndpointConnections,omitempty" azure:"ro"`

	// READ-ONLY; The state of the last provisioning operation performed on the search service. Provisioning is an intermediate state that occurs while service
	// capacity is being established. After capacity is set up,
	// provisioningState changes to either 'succeeded' or 'failed'. Client applications can poll provisioning status (the recommended polling interval is from
	// 30 seconds to one minute) by using the Get
	// Search Service operation to see when an operation is completed. If you are using the free service, this value tends to come back as 'succeeded' directly
	// in the call to Create search service. This is
	// because the free service uses capacity that is already set up.
	ProvisioningState *ProvisioningState `json:"provisioningState,omitempty" azure:"ro"`

	// READ-ONLY; The list of shared private link resources managed by the Azure Cognitive Search service.
	SharedPrivateLinkResources []*SharedPrivateLinkResource `json:"sharedPrivateLinkResources,omitempty" azure:"ro"`

	// READ-ONLY; The status of the search service. Possible values include: 'running': The search service is running and no provisioning operations are underway.
	// 'provisioning': The search service is being provisioned
	// or scaled up or down. 'deleting': The search service is being deleted. 'degraded': The search service is degraded. This can occur when the underlying
	// search units are not healthy. The search service
	// is most likely operational, but performance might be slow and some requests might be dropped. 'disabled': The search service is disabled. In this state,
	// the service will reject all API requests.
	// 'error': The search service is in an error state. If your service is in the degraded, disabled, or error states, it means the Azure Cognitive Search
	// team is actively investigating the underlying
	// issue. Dedicated services in these states are still chargeable based on the number of search units provisioned.
	Status *SearchServiceStatus `json:"status,omitempty" azure:"ro"`

	// READ-ONLY; The details of the search service status.
	StatusDetails *string `json:"statusDetails,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type SearchServiceProperties.
func (s SearchServiceProperties) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "hostingMode", s.HostingMode)
	populate(objectMap, "networkRuleSet", s.NetworkRuleSet)
	populate(objectMap, "partitionCount", s.PartitionCount)
	populate(objectMap, "privateEndpointConnections", s.PrivateEndpointConnections)
	populate(objectMap, "provisioningState", s.ProvisioningState)
	populate(objectMap, "publicNetworkAccess", s.PublicNetworkAccess)
	populate(objectMap, "replicaCount", s.ReplicaCount)
	populate(objectMap, "sharedPrivateLinkResources", s.SharedPrivateLinkResources)
	populate(objectMap, "status", s.Status)
	populate(objectMap, "statusDetails", s.StatusDetails)
	return json.Marshal(objectMap)
}

// SearchServiceUpdate - The parameters used to update an Azure Cognitive Search service.
type SearchServiceUpdate struct {
	Resource
	// The identity of the resource.
	Identity *Identity `json:"identity,omitempty"`

	// The geographic location of the resource. This must be one of the supported and registered Azure Geo Regions (for example, West US, East US, Southeast
	// Asia, and so forth). This property is required
	// when creating a new resource.
	Location *string `json:"location,omitempty"`

	// Properties of the search service.
	Properties *SearchServiceProperties `json:"properties,omitempty"`

	// The SKU of the Search Service, which determines price tier and capacity limits. This property is required when creating a new Search Service.
	SKU *SKU `json:"sku,omitempty"`

	// Tags to help categorize the resource in the Azure portal.
	Tags map[string]*string `json:"tags,omitempty"`
}

// MarshalJSON implements the json.Marshaller interface for type SearchServiceUpdate.
func (s SearchServiceUpdate) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	s.Resource.marshalInternal(objectMap)
	populate(objectMap, "identity", s.Identity)
	populate(objectMap, "location", s.Location)
	populate(objectMap, "properties", s.Properties)
	populate(objectMap, "sku", s.SKU)
	populate(objectMap, "tags", s.Tags)
	return json.Marshal(objectMap)
}

// ServicesBeginCreateOrUpdateOptions contains the optional parameters for the Services.BeginCreateOrUpdate method.
type ServicesBeginCreateOrUpdateOptions struct {
	// placeholder for future optional parameters
}

// ServicesCheckNameAvailabilityOptions contains the optional parameters for the Services.CheckNameAvailability method.
type ServicesCheckNameAvailabilityOptions struct {
	// placeholder for future optional parameters
}

// ServicesDeleteOptions contains the optional parameters for the Services.Delete method.
type ServicesDeleteOptions struct {
	// placeholder for future optional parameters
}

// ServicesGetOptions contains the optional parameters for the Services.Get method.
type ServicesGetOptions struct {
	// placeholder for future optional parameters
}

// ServicesListByResourceGroupOptions contains the optional parameters for the Services.ListByResourceGroup method.
type ServicesListByResourceGroupOptions struct {
	// placeholder for future optional parameters
}

// ServicesListBySubscriptionOptions contains the optional parameters for the Services.ListBySubscription method.
type ServicesListBySubscriptionOptions struct {
	// placeholder for future optional parameters
}

// ServicesUpdateOptions contains the optional parameters for the Services.Update method.
type ServicesUpdateOptions struct {
	// placeholder for future optional parameters
}

// ShareablePrivateLinkResourceProperties - Describes the properties of a resource type that has been onboarded to private link service, supported by Azure
// Cognitive Search.
type ShareablePrivateLinkResourceProperties struct {
	// READ-ONLY; The description of the resource type that has been onboarded to private link service, supported by Azure Cognitive Search.
	Description *string `json:"description,omitempty" azure:"ro"`

	// READ-ONLY; The resource provider group id for the resource that has been onboarded to private link service, supported by Azure Cognitive Search.
	GroupID *string `json:"groupId,omitempty" azure:"ro"`

	// READ-ONLY; The resource provider type for the resource that has been onboarded to private link service, supported by Azure Cognitive Search.
	Type *string `json:"type,omitempty" azure:"ro"`
}

// ShareablePrivateLinkResourceType - Describes an resource type that has been onboarded to private link service, supported by Azure Cognitive Search.
type ShareablePrivateLinkResourceType struct {
	// READ-ONLY; The name of the resource type that has been onboarded to private link service, supported by Azure Cognitive Search.
	Name *string `json:"name,omitempty" azure:"ro"`

	// READ-ONLY; Describes the properties of a resource type that has been onboarded to private link service, supported by Azure Cognitive Search.
	Properties *ShareablePrivateLinkResourceProperties `json:"properties,omitempty" azure:"ro"`
}

// SharedPrivateLinkResource - Describes a Shared Private Link Resource managed by the Azure Cognitive Search service.
type SharedPrivateLinkResource struct {
	Resource
	// Describes the properties of a Shared Private Link Resource managed by the Azure Cognitive Search service.
	Properties *SharedPrivateLinkResourceProperties `json:"properties,omitempty"`
}

// MarshalJSON implements the json.Marshaller interface for type SharedPrivateLinkResource.
func (s SharedPrivateLinkResource) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	s.Resource.marshalInternal(objectMap)
	populate(objectMap, "properties", s.Properties)
	return json.Marshal(objectMap)
}

// SharedPrivateLinkResourceListResult - Response containing a list of Shared Private Link Resources.
type SharedPrivateLinkResourceListResult struct {
	// The URL to get the next set of shared private link resources, if there are any.
	NextLink *string `json:"nextLink,omitempty"`

	// READ-ONLY; The list of Shared Private Link Resources.
	Value []*SharedPrivateLinkResource `json:"value,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type SharedPrivateLinkResourceListResult.
func (s SharedPrivateLinkResourceListResult) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "nextLink", s.NextLink)
	populate(objectMap, "value", s.Value)
	return json.Marshal(objectMap)
}

// SharedPrivateLinkResourceProperties - Describes the properties of an existing Shared Private Link Resource managed by the Azure Cognitive Search service.
type SharedPrivateLinkResourceProperties struct {
	// The group id from the provider of resource the shared private link resource is for.
	GroupID *string `json:"groupId,omitempty"`

	// The resource id of the resource the shared private link resource is for.
	PrivateLinkResourceID *string `json:"privateLinkResourceId,omitempty"`

	// The provisioning state of the shared private link resource. Can be Updating, Deleting, Failed, Succeeded or Incomplete.
	ProvisioningState *SharedPrivateLinkResourceProvisioningState `json:"provisioningState,omitempty"`

	// The request message for requesting approval of the shared private link resource.
	RequestMessage *string `json:"requestMessage,omitempty"`

	// Optional. Can be used to specify the Azure Resource Manager location of the resource to which a shared private link is to be created. This is only required
	// for those resources whose DNS configuration
	// are regional (such as Azure Kubernetes Service).
	ResourceRegion *string `json:"resourceRegion,omitempty"`

	// Status of the shared private link resource. Can be Pending, Approved, Rejected or Disconnected.
	Status *SharedPrivateLinkResourceStatus `json:"status,omitempty"`
}

// SharedPrivateLinkResourcesBeginCreateOrUpdateOptions contains the optional parameters for the SharedPrivateLinkResources.BeginCreateOrUpdate method.
type SharedPrivateLinkResourcesBeginCreateOrUpdateOptions struct {
	// placeholder for future optional parameters
}

// SharedPrivateLinkResourcesBeginDeleteOptions contains the optional parameters for the SharedPrivateLinkResources.BeginDelete method.
type SharedPrivateLinkResourcesBeginDeleteOptions struct {
	// placeholder for future optional parameters
}

// SharedPrivateLinkResourcesGetOptions contains the optional parameters for the SharedPrivateLinkResources.Get method.
type SharedPrivateLinkResourcesGetOptions struct {
	// placeholder for future optional parameters
}

// SharedPrivateLinkResourcesListByServiceOptions contains the optional parameters for the SharedPrivateLinkResources.ListByService method.
type SharedPrivateLinkResourcesListByServiceOptions struct {
	// placeholder for future optional parameters
}

// TrackedResource - The resource model definition for an Azure Resource Manager tracked top level resource which has 'tags' and a 'location'
type TrackedResource struct {
	Resource
	// REQUIRED; The geo-location where the resource lives
	Location *string `json:"location,omitempty"`

	// Resource tags.
	Tags map[string]*string `json:"tags,omitempty"`
}

// MarshalJSON implements the json.Marshaller interface for type TrackedResource.
func (t TrackedResource) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	t.marshalInternal(objectMap)
	return json.Marshal(objectMap)
}

func (t TrackedResource) marshalInternal(objectMap map[string]interface{}) {
	t.Resource.marshalInternal(objectMap)
	populate(objectMap, "location", t.Location)
	populate(objectMap, "tags", t.Tags)
}

func populate(m map[string]interface{}, k string, v interface{}) {
	if v == nil {
		return
	} else if azcore.IsNullValue(v) {
		m[k] = nil
	} else if !reflect.ValueOf(v).IsNil() {
		m[k] = v
	}
}