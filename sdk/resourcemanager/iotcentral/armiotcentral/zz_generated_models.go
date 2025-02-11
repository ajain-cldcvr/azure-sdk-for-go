//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armiotcentral

import (
	"encoding/json"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"reflect"
)

// App - The IoT Central application.
type App struct {
	// REQUIRED; The resource location.
	Location *string `json:"location,omitempty"`

	// REQUIRED; A valid instance SKU.
	SKU *AppSKUInfo `json:"sku,omitempty"`

	// The managed identities for the IoT Central application.
	Identity *SystemAssignedServiceIdentity `json:"identity,omitempty"`

	// The common properties of an IoT Central application.
	Properties *AppProperties `json:"properties,omitempty"`

	// The resource tags.
	Tags map[string]*string `json:"tags,omitempty"`

	// READ-ONLY; The ARM resource identifier.
	ID *string `json:"id,omitempty" azure:"ro"`

	// READ-ONLY; The ARM resource name.
	Name *string `json:"name,omitempty" azure:"ro"`

	// READ-ONLY; The resource type.
	Type *string `json:"type,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type App.
func (a App) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "id", a.ID)
	populate(objectMap, "identity", a.Identity)
	populate(objectMap, "location", a.Location)
	populate(objectMap, "name", a.Name)
	populate(objectMap, "properties", a.Properties)
	populate(objectMap, "sku", a.SKU)
	populate(objectMap, "tags", a.Tags)
	populate(objectMap, "type", a.Type)
	return json.Marshal(objectMap)
}

// AppAvailabilityInfo - The properties indicating whether a given IoT Central application name or subdomain is available.
type AppAvailabilityInfo struct {
	// READ-ONLY; The detailed reason message.
	Message *string `json:"message,omitempty" azure:"ro"`

	// READ-ONLY; The value which indicates whether the provided name is available.
	NameAvailable *bool `json:"nameAvailable,omitempty" azure:"ro"`

	// READ-ONLY; The reason for unavailability.
	Reason *string `json:"reason,omitempty" azure:"ro"`
}

// AppListResult - A list of IoT Central Applications with a next link.
type AppListResult struct {
	// The link used to get the next page of IoT Central Applications.
	NextLink *string `json:"nextLink,omitempty"`

	// A list of IoT Central Applications.
	Value []*App `json:"value,omitempty"`
}

// MarshalJSON implements the json.Marshaller interface for type AppListResult.
func (a AppListResult) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "nextLink", a.NextLink)
	populate(objectMap, "value", a.Value)
	return json.Marshal(objectMap)
}

// AppPatch - The description of the IoT Central application.
type AppPatch struct {
	// The managed identities for the IoT Central application.
	Identity *SystemAssignedServiceIdentity `json:"identity,omitempty"`

	// The common properties of an IoT Central application.
	Properties *AppProperties `json:"properties,omitempty"`

	// A valid instance SKU.
	SKU *AppSKUInfo `json:"sku,omitempty"`

	// Instance tags
	Tags map[string]*string `json:"tags,omitempty"`
}

// MarshalJSON implements the json.Marshaller interface for type AppPatch.
func (a AppPatch) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "identity", a.Identity)
	populate(objectMap, "properties", a.Properties)
	populate(objectMap, "sku", a.SKU)
	populate(objectMap, "tags", a.Tags)
	return json.Marshal(objectMap)
}

// AppProperties - The properties of an IoT Central application.
type AppProperties struct {
	// The display name of the application.
	DisplayName *string `json:"displayName,omitempty"`

	// The subdomain of the application.
	Subdomain *string `json:"subdomain,omitempty"`

	// The ID of the application template, which is a blueprint that defines the characteristics and behaviors of an application.
	// Optional; if not specified, defaults to a blank blueprint and allows the
	// application to be defined from scratch.
	Template *string `json:"template,omitempty"`

	// READ-ONLY; The ID of the application.
	ApplicationID *string `json:"applicationId,omitempty" azure:"ro"`

	// READ-ONLY; The current state of the application.
	State *AppState `json:"state,omitempty" azure:"ro"`
}

// AppSKUInfo - Information about the SKU of the IoT Central application.
type AppSKUInfo struct {
	// REQUIRED; The name of the SKU.
	Name *AppSKU `json:"name,omitempty"`
}

// AppTemplate - IoT Central Application Template.
type AppTemplate struct {
	// READ-ONLY; The description of the template.
	Description *string `json:"description,omitempty" azure:"ro"`

	// READ-ONLY; The industry of the template.
	Industry *string `json:"industry,omitempty" azure:"ro"`

	// READ-ONLY; A list of locations that support the template.
	Locations []*AppTemplateLocations `json:"locations,omitempty" azure:"ro"`

	// READ-ONLY; The ID of the template.
	ManifestID *string `json:"manifestId,omitempty" azure:"ro"`

	// READ-ONLY; The version of the template.
	ManifestVersion *string `json:"manifestVersion,omitempty" azure:"ro"`

	// READ-ONLY; The name of the template.
	Name *string `json:"name,omitempty" azure:"ro"`

	// READ-ONLY; The order of the template in the templates list.
	Order *float32 `json:"order,omitempty" azure:"ro"`

	// READ-ONLY; The title of the template.
	Title *string `json:"title,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type AppTemplate.
func (a AppTemplate) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "description", a.Description)
	populate(objectMap, "industry", a.Industry)
	populate(objectMap, "locations", a.Locations)
	populate(objectMap, "manifestId", a.ManifestID)
	populate(objectMap, "manifestVersion", a.ManifestVersion)
	populate(objectMap, "name", a.Name)
	populate(objectMap, "order", a.Order)
	populate(objectMap, "title", a.Title)
	return json.Marshal(objectMap)
}

// AppTemplateLocations - IoT Central Application Template Locations.
type AppTemplateLocations struct {
	// READ-ONLY; The display name of the location.
	DisplayName *string `json:"displayName,omitempty" azure:"ro"`

	// READ-ONLY; The ID of the location.
	ID *string `json:"id,omitempty" azure:"ro"`
}

// AppTemplatesResult - A list of IoT Central Application Templates with a next link.
type AppTemplatesResult struct {
	// The link used to get the next page of IoT Central application templates.
	NextLink *string `json:"nextLink,omitempty"`

	// READ-ONLY; A list of IoT Central Application Templates.
	Value []*AppTemplate `json:"value,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type AppTemplatesResult.
func (a AppTemplatesResult) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "nextLink", a.NextLink)
	populate(objectMap, "value", a.Value)
	return json.Marshal(objectMap)
}

// AppsClientBeginCreateOrUpdateOptions contains the optional parameters for the AppsClient.BeginCreateOrUpdate method.
type AppsClientBeginCreateOrUpdateOptions struct {
	// placeholder for future optional parameters
}

// AppsClientBeginDeleteOptions contains the optional parameters for the AppsClient.BeginDelete method.
type AppsClientBeginDeleteOptions struct {
	// placeholder for future optional parameters
}

// AppsClientBeginUpdateOptions contains the optional parameters for the AppsClient.BeginUpdate method.
type AppsClientBeginUpdateOptions struct {
	// placeholder for future optional parameters
}

// AppsClientCheckNameAvailabilityOptions contains the optional parameters for the AppsClient.CheckNameAvailability method.
type AppsClientCheckNameAvailabilityOptions struct {
	// placeholder for future optional parameters
}

// AppsClientCheckSubdomainAvailabilityOptions contains the optional parameters for the AppsClient.CheckSubdomainAvailability
// method.
type AppsClientCheckSubdomainAvailabilityOptions struct {
	// placeholder for future optional parameters
}

// AppsClientGetOptions contains the optional parameters for the AppsClient.Get method.
type AppsClientGetOptions struct {
	// placeholder for future optional parameters
}

// AppsClientListByResourceGroupOptions contains the optional parameters for the AppsClient.ListByResourceGroup method.
type AppsClientListByResourceGroupOptions struct {
	// placeholder for future optional parameters
}

// AppsClientListBySubscriptionOptions contains the optional parameters for the AppsClient.ListBySubscription method.
type AppsClientListBySubscriptionOptions struct {
	// placeholder for future optional parameters
}

// AppsClientListTemplatesOptions contains the optional parameters for the AppsClient.ListTemplates method.
type AppsClientListTemplatesOptions struct {
	// placeholder for future optional parameters
}

// CloudError - Error details.
type CloudError struct {
	// Error response body.
	Error *CloudErrorBody `json:"error,omitempty"`
}

// CloudErrorBody - Details of error response.
type CloudErrorBody struct {
	// A list of additional details about the error.
	Details []*CloudErrorBody `json:"details,omitempty"`

	// READ-ONLY; The error code.
	Code *string `json:"code,omitempty" azure:"ro"`

	// READ-ONLY; The error message.
	Message *string `json:"message,omitempty" azure:"ro"`

	// READ-ONLY; The target of the particular error.
	Target *string `json:"target,omitempty" azure:"ro"`
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

// Operation - IoT Central REST API operation
type Operation struct {
	// The object that represents the operation.
	Display *OperationDisplay `json:"display,omitempty"`

	// READ-ONLY; Operation name: {provider}/{resource}/{read | write | action | delete}
	Name *string `json:"name,omitempty" azure:"ro"`

	// READ-ONLY; The intended executor of the operation.
	Origin *string `json:"origin,omitempty" azure:"ro"`

	// READ-ONLY; Additional descriptions for the operation.
	Properties map[string]interface{} `json:"properties,omitempty" azure:"ro"`
}

// OperationDisplay - The object that represents the operation.
type OperationDisplay struct {
	// READ-ONLY; Friendly description for the operation,
	Description *string `json:"description,omitempty" azure:"ro"`

	// READ-ONLY; Name of the operation
	Operation *string `json:"operation,omitempty" azure:"ro"`

	// READ-ONLY; Service provider: Microsoft IoT Central
	Provider *string `json:"provider,omitempty" azure:"ro"`

	// READ-ONLY; Resource Type: IoT Central
	Resource *string `json:"resource,omitempty" azure:"ro"`
}

// OperationInputs - Input values.
type OperationInputs struct {
	// REQUIRED; The name of the IoT Central application instance to check.
	Name *string `json:"name,omitempty"`

	// The type of the IoT Central resource to query.
	Type *string `json:"type,omitempty"`
}

// OperationListResult - A list of IoT Central operations. It contains a list of operations and a URL link to get the next
// set of results.
type OperationListResult struct {
	// The link used to get the next page of IoT Central description objects.
	NextLink *string `json:"nextLink,omitempty"`

	// READ-ONLY; A list of operations supported by the Microsoft.IoTCentral resource provider.
	Value []*Operation `json:"value,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type OperationListResult.
func (o OperationListResult) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "nextLink", o.NextLink)
	populate(objectMap, "value", o.Value)
	return json.Marshal(objectMap)
}

// OperationsClientListOptions contains the optional parameters for the OperationsClient.List method.
type OperationsClientListOptions struct {
	// placeholder for future optional parameters
}

// Resource - The common properties of an ARM resource.
type Resource struct {
	// REQUIRED; The resource location.
	Location *string `json:"location,omitempty"`

	// The resource tags.
	Tags map[string]*string `json:"tags,omitempty"`

	// READ-ONLY; The ARM resource identifier.
	ID *string `json:"id,omitempty" azure:"ro"`

	// READ-ONLY; The ARM resource name.
	Name *string `json:"name,omitempty" azure:"ro"`

	// READ-ONLY; The resource type.
	Type *string `json:"type,omitempty" azure:"ro"`
}

// MarshalJSON implements the json.Marshaller interface for type Resource.
func (r Resource) MarshalJSON() ([]byte, error) {
	objectMap := make(map[string]interface{})
	populate(objectMap, "id", r.ID)
	populate(objectMap, "location", r.Location)
	populate(objectMap, "name", r.Name)
	populate(objectMap, "tags", r.Tags)
	populate(objectMap, "type", r.Type)
	return json.Marshal(objectMap)
}

// SystemAssignedServiceIdentity - Managed service identity (either system assigned, or none)
type SystemAssignedServiceIdentity struct {
	// REQUIRED; Type of managed service identity (either system assigned, or none).
	Type *SystemAssignedServiceIdentityType `json:"type,omitempty"`

	// READ-ONLY; The service principal ID of the system assigned identity. This property will only be provided for a system assigned
	// identity.
	PrincipalID *string `json:"principalId,omitempty" azure:"ro"`

	// READ-ONLY; The tenant ID of the system assigned identity. This property will only be provided for a system assigned identity.
	TenantID *string `json:"tenantId,omitempty" azure:"ro"`
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
