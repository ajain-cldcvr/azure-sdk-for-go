//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armvideoanalyzer

const (
	moduleName    = "armvideoanalyzer"
	moduleVersion = "v0.2.1"
)

// AccessPolicyEccAlgo - Elliptical curve algorithm to be used: ES256, ES384 or ES512.
type AccessPolicyEccAlgo string

const (
	// AccessPolicyEccAlgoES256 - ES265
	AccessPolicyEccAlgoES256 AccessPolicyEccAlgo = "ES256"
	// AccessPolicyEccAlgoES384 - ES384
	AccessPolicyEccAlgoES384 AccessPolicyEccAlgo = "ES384"
	// AccessPolicyEccAlgoES512 - ES512
	AccessPolicyEccAlgoES512 AccessPolicyEccAlgo = "ES512"
)

// PossibleAccessPolicyEccAlgoValues returns the possible values for the AccessPolicyEccAlgo const type.
func PossibleAccessPolicyEccAlgoValues() []AccessPolicyEccAlgo {
	return []AccessPolicyEccAlgo{
		AccessPolicyEccAlgoES256,
		AccessPolicyEccAlgoES384,
		AccessPolicyEccAlgoES512,
	}
}

// ToPtr returns a *AccessPolicyEccAlgo pointing to the current value.
func (c AccessPolicyEccAlgo) ToPtr() *AccessPolicyEccAlgo {
	return &c
}

// AccessPolicyRole - Defines the access level granted by this policy.
type AccessPolicyRole string

const (
	// AccessPolicyRoleReader - Reader role allows for read-only operations to be performed through the client APIs.
	AccessPolicyRoleReader AccessPolicyRole = "Reader"
)

// PossibleAccessPolicyRoleValues returns the possible values for the AccessPolicyRole const type.
func PossibleAccessPolicyRoleValues() []AccessPolicyRole {
	return []AccessPolicyRole{
		AccessPolicyRoleReader,
	}
}

// ToPtr returns a *AccessPolicyRole pointing to the current value.
func (c AccessPolicyRole) ToPtr() *AccessPolicyRole {
	return &c
}

// AccessPolicyRsaAlgo - RSA algorithm to be used: RS256, RS384 or RS512.
type AccessPolicyRsaAlgo string

const (
	// AccessPolicyRsaAlgoRS256 - RS256
	AccessPolicyRsaAlgoRS256 AccessPolicyRsaAlgo = "RS256"
	// AccessPolicyRsaAlgoRS384 - RS384
	AccessPolicyRsaAlgoRS384 AccessPolicyRsaAlgo = "RS384"
	// AccessPolicyRsaAlgoRS512 - RS512
	AccessPolicyRsaAlgoRS512 AccessPolicyRsaAlgo = "RS512"
)

// PossibleAccessPolicyRsaAlgoValues returns the possible values for the AccessPolicyRsaAlgo const type.
func PossibleAccessPolicyRsaAlgoValues() []AccessPolicyRsaAlgo {
	return []AccessPolicyRsaAlgo{
		AccessPolicyRsaAlgoRS256,
		AccessPolicyRsaAlgoRS384,
		AccessPolicyRsaAlgoRS512,
	}
}

// ToPtr returns a *AccessPolicyRsaAlgo pointing to the current value.
func (c AccessPolicyRsaAlgo) ToPtr() *AccessPolicyRsaAlgo {
	return &c
}

// AccountEncryptionKeyType - The type of key used to encrypt the Account Key.
type AccountEncryptionKeyType string

const (
	// AccountEncryptionKeyTypeCustomerKey - The Account Key is encrypted with a Customer Key.
	AccountEncryptionKeyTypeCustomerKey AccountEncryptionKeyType = "CustomerKey"
	// AccountEncryptionKeyTypeSystemKey - The Account Key is encrypted with a System Key.
	AccountEncryptionKeyTypeSystemKey AccountEncryptionKeyType = "SystemKey"
)

// PossibleAccountEncryptionKeyTypeValues returns the possible values for the AccountEncryptionKeyType const type.
func PossibleAccountEncryptionKeyTypeValues() []AccountEncryptionKeyType {
	return []AccountEncryptionKeyType{
		AccountEncryptionKeyTypeCustomerKey,
		AccountEncryptionKeyTypeSystemKey,
	}
}

// ToPtr returns a *AccountEncryptionKeyType pointing to the current value.
func (c AccountEncryptionKeyType) ToPtr() *AccountEncryptionKeyType {
	return &c
}

// ActionType - Indicates the action type.
type ActionType string

const (
	// ActionTypeInternal - An internal action.
	ActionTypeInternal ActionType = "Internal"
)

// PossibleActionTypeValues returns the possible values for the ActionType const type.
func PossibleActionTypeValues() []ActionType {
	return []ActionType{
		ActionTypeInternal,
	}
}

// ToPtr returns a *ActionType pointing to the current value.
func (c ActionType) ToPtr() *ActionType {
	return &c
}

// CheckNameAvailabilityReason - The reason why the given name is not available.
type CheckNameAvailabilityReason string

const (
	CheckNameAvailabilityReasonAlreadyExists CheckNameAvailabilityReason = "AlreadyExists"
	CheckNameAvailabilityReasonInvalid       CheckNameAvailabilityReason = "Invalid"
)

// PossibleCheckNameAvailabilityReasonValues returns the possible values for the CheckNameAvailabilityReason const type.
func PossibleCheckNameAvailabilityReasonValues() []CheckNameAvailabilityReason {
	return []CheckNameAvailabilityReason{
		CheckNameAvailabilityReasonAlreadyExists,
		CheckNameAvailabilityReasonInvalid,
	}
}

// ToPtr returns a *CheckNameAvailabilityReason pointing to the current value.
func (c CheckNameAvailabilityReason) ToPtr() *CheckNameAvailabilityReason {
	return &c
}

// CreatedByType - The type of identity that created the resource.
type CreatedByType string

const (
	CreatedByTypeApplication     CreatedByType = "Application"
	CreatedByTypeKey             CreatedByType = "Key"
	CreatedByTypeManagedIdentity CreatedByType = "ManagedIdentity"
	CreatedByTypeUser            CreatedByType = "User"
)

// PossibleCreatedByTypeValues returns the possible values for the CreatedByType const type.
func PossibleCreatedByTypeValues() []CreatedByType {
	return []CreatedByType{
		CreatedByTypeApplication,
		CreatedByTypeKey,
		CreatedByTypeManagedIdentity,
		CreatedByTypeUser,
	}
}

// ToPtr returns a *CreatedByType pointing to the current value.
func (c CreatedByType) ToPtr() *CreatedByType {
	return &c
}

// EncoderSystemPresetType - Name of the built-in encoding preset.
type EncoderSystemPresetType string

const (
	// EncoderSystemPresetTypeSingleLayer1080PH264AAC - Produces an MP4 file where the video is encoded with H.264 codec at a
	// picture height of 1080 pixels, and at a maximum bitrate of 6000 Kbps. Encoded video has the same average frame rate as
	// the input. The aspect ratio of the input is preserved. If the input content has audio, then it is encoded with AAC-LC codec
	// at 128 Kbps
	EncoderSystemPresetTypeSingleLayer1080PH264AAC EncoderSystemPresetType = "SingleLayer_1080p_H264_AAC"
	// EncoderSystemPresetTypeSingleLayer2160PH264AAC - Produces an MP4 file where the video is encoded with H.264 codec at a
	// picture height of 2160 pixels, and at a maximum bitrate of 16000 Kbps. Encoded video has the same average frame rate as
	// the input. The aspect ratio of the input is preserved. If the input content has audio, then it is encoded with AAC-LC codec
	// at 128 Kbps
	EncoderSystemPresetTypeSingleLayer2160PH264AAC EncoderSystemPresetType = "SingleLayer_2160p_H264_AAC"
	// EncoderSystemPresetTypeSingleLayer540PH264AAC - Produces an MP4 file where the video is encoded with H.264 codec at a picture
	// height of 540 pixels, and at a maximum bitrate of 2000 Kbps. Encoded video has the same average frame rate as the input.
	// The aspect ratio of the input is preserved. If the input content has audio, then it is encoded with AAC-LC codec at 96
	// Kbps
	EncoderSystemPresetTypeSingleLayer540PH264AAC EncoderSystemPresetType = "SingleLayer_540p_H264_AAC"
	// EncoderSystemPresetTypeSingleLayer720PH264AAC - Produces an MP4 file where the video is encoded with H.264 codec at a picture
	// height of 720 pixels, and at a maximum bitrate of 3500 Kbps. Encoded video has the same average frame rate as the input.
	// The aspect ratio of the input is preserved. If the input content has audio, then it is encoded with AAC-LC codec at 96
	// Kbps
	EncoderSystemPresetTypeSingleLayer720PH264AAC EncoderSystemPresetType = "SingleLayer_720p_H264_AAC"
)

// PossibleEncoderSystemPresetTypeValues returns the possible values for the EncoderSystemPresetType const type.
func PossibleEncoderSystemPresetTypeValues() []EncoderSystemPresetType {
	return []EncoderSystemPresetType{
		EncoderSystemPresetTypeSingleLayer1080PH264AAC,
		EncoderSystemPresetTypeSingleLayer2160PH264AAC,
		EncoderSystemPresetTypeSingleLayer540PH264AAC,
		EncoderSystemPresetTypeSingleLayer720PH264AAC,
	}
}

// ToPtr returns a *EncoderSystemPresetType pointing to the current value.
func (c EncoderSystemPresetType) ToPtr() *EncoderSystemPresetType {
	return &c
}

// Kind - Topology kind.
type Kind string

const (
	// KindBatch - Batch pipeline topology resource.
	KindBatch Kind = "Batch"
	// KindLive - Live pipeline topology resource.
	KindLive Kind = "Live"
)

// PossibleKindValues returns the possible values for the Kind const type.
func PossibleKindValues() []Kind {
	return []Kind{
		KindBatch,
		KindLive,
	}
}

// ToPtr returns a *Kind pointing to the current value.
func (c Kind) ToPtr() *Kind {
	return &c
}

// LivePipelineState - Current state of the pipeline (read-only).
type LivePipelineState string

const (
	// LivePipelineStateActivating - The live pipeline is transitioning into the active state.
	LivePipelineStateActivating LivePipelineState = "Activating"
	// LivePipelineStateActive - The live pipeline is active and able to process media. If your data source is not available,
	// for instance, if your RTSP camera is powered off or unreachable, the pipeline will still be active and periodically retrying
	// the connection. Your Azure subscription will be billed for the duration in which the live pipeline is in the active state.
	LivePipelineStateActive LivePipelineState = "Active"
	// LivePipelineStateDeactivating - The live pipeline is transitioning into the inactive state.
	LivePipelineStateDeactivating LivePipelineState = "Deactivating"
	// LivePipelineStateInactive - The live pipeline is idle and not processing media.
	LivePipelineStateInactive LivePipelineState = "Inactive"
)

// PossibleLivePipelineStateValues returns the possible values for the LivePipelineState const type.
func PossibleLivePipelineStateValues() []LivePipelineState {
	return []LivePipelineState{
		LivePipelineStateActivating,
		LivePipelineStateActive,
		LivePipelineStateDeactivating,
		LivePipelineStateInactive,
	}
}

// ToPtr returns a *LivePipelineState pointing to the current value.
func (c LivePipelineState) ToPtr() *LivePipelineState {
	return &c
}

// MetricAggregationType - The metric aggregation type
type MetricAggregationType string

const (
	// MetricAggregationTypeAverage - The average.
	MetricAggregationTypeAverage MetricAggregationType = "Average"
	// MetricAggregationTypeCount - The count of a number of items, usually requests.
	MetricAggregationTypeCount MetricAggregationType = "Count"
	// MetricAggregationTypeTotal - The sum.
	MetricAggregationTypeTotal MetricAggregationType = "Total"
)

// PossibleMetricAggregationTypeValues returns the possible values for the MetricAggregationType const type.
func PossibleMetricAggregationTypeValues() []MetricAggregationType {
	return []MetricAggregationType{
		MetricAggregationTypeAverage,
		MetricAggregationTypeCount,
		MetricAggregationTypeTotal,
	}
}

// ToPtr returns a *MetricAggregationType pointing to the current value.
func (c MetricAggregationType) ToPtr() *MetricAggregationType {
	return &c
}

// MetricUnit - The metric unit
type MetricUnit string

const (
	// MetricUnitBytes - The number of bytes.
	MetricUnitBytes MetricUnit = "Bytes"
	// MetricUnitCount - The count.
	MetricUnitCount MetricUnit = "Count"
	// MetricUnitMilliseconds - The number of milliseconds.
	MetricUnitMilliseconds MetricUnit = "Milliseconds"
)

// PossibleMetricUnitValues returns the possible values for the MetricUnit const type.
func PossibleMetricUnitValues() []MetricUnit {
	return []MetricUnit{
		MetricUnitBytes,
		MetricUnitCount,
		MetricUnitMilliseconds,
	}
}

// ToPtr returns a *MetricUnit pointing to the current value.
func (c MetricUnit) ToPtr() *MetricUnit {
	return &c
}

// ParameterType - Type of the parameter.
type ParameterType string

const (
	// ParameterTypeBool - The parameter's value is a boolean value that is either true or false.
	ParameterTypeBool ParameterType = "Bool"
	// ParameterTypeDouble - The parameter's value is a 64-bit double-precision floating point.
	ParameterTypeDouble ParameterType = "Double"
	// ParameterTypeInt - The parameter's value is a 32-bit signed integer.
	ParameterTypeInt ParameterType = "Int"
	// ParameterTypeSecretString - The parameter's value is a string that holds sensitive information.
	ParameterTypeSecretString ParameterType = "SecretString"
	// ParameterTypeString - The parameter's value is a string.
	ParameterTypeString ParameterType = "String"
)

// PossibleParameterTypeValues returns the possible values for the ParameterType const type.
func PossibleParameterTypeValues() []ParameterType {
	return []ParameterType{
		ParameterTypeBool,
		ParameterTypeDouble,
		ParameterTypeInt,
		ParameterTypeSecretString,
		ParameterTypeString,
	}
}

// ToPtr returns a *ParameterType pointing to the current value.
func (c ParameterType) ToPtr() *ParameterType {
	return &c
}

// PipelineJobState - Current state of the pipeline (read-only).
type PipelineJobState string

const (
	// PipelineJobStateCanceled - Pipeline job is canceled.
	PipelineJobStateCanceled PipelineJobState = "Canceled"
	// PipelineJobStateCompleted - Pipeline job completed.
	PipelineJobStateCompleted PipelineJobState = "Completed"
	// PipelineJobStateFailed - Pipeline job failed.
	PipelineJobStateFailed PipelineJobState = "Failed"
	// PipelineJobStateProcessing - Pipeline job is processing.
	PipelineJobStateProcessing PipelineJobState = "Processing"
)

// PossiblePipelineJobStateValues returns the possible values for the PipelineJobState const type.
func PossiblePipelineJobStateValues() []PipelineJobState {
	return []PipelineJobState{
		PipelineJobStateCanceled,
		PipelineJobStateCompleted,
		PipelineJobStateFailed,
		PipelineJobStateProcessing,
	}
}

// ToPtr returns a *PipelineJobState pointing to the current value.
func (c PipelineJobState) ToPtr() *PipelineJobState {
	return &c
}

// PrivateEndpointConnectionProvisioningState - The current provisioning state.
type PrivateEndpointConnectionProvisioningState string

const (
	PrivateEndpointConnectionProvisioningStateCreating  PrivateEndpointConnectionProvisioningState = "Creating"
	PrivateEndpointConnectionProvisioningStateDeleting  PrivateEndpointConnectionProvisioningState = "Deleting"
	PrivateEndpointConnectionProvisioningStateFailed    PrivateEndpointConnectionProvisioningState = "Failed"
	PrivateEndpointConnectionProvisioningStateSucceeded PrivateEndpointConnectionProvisioningState = "Succeeded"
)

// PossiblePrivateEndpointConnectionProvisioningStateValues returns the possible values for the PrivateEndpointConnectionProvisioningState const type.
func PossiblePrivateEndpointConnectionProvisioningStateValues() []PrivateEndpointConnectionProvisioningState {
	return []PrivateEndpointConnectionProvisioningState{
		PrivateEndpointConnectionProvisioningStateCreating,
		PrivateEndpointConnectionProvisioningStateDeleting,
		PrivateEndpointConnectionProvisioningStateFailed,
		PrivateEndpointConnectionProvisioningStateSucceeded,
	}
}

// ToPtr returns a *PrivateEndpointConnectionProvisioningState pointing to the current value.
func (c PrivateEndpointConnectionProvisioningState) ToPtr() *PrivateEndpointConnectionProvisioningState {
	return &c
}

// PrivateEndpointServiceConnectionStatus - The private endpoint connection status.
type PrivateEndpointServiceConnectionStatus string

const (
	PrivateEndpointServiceConnectionStatusApproved PrivateEndpointServiceConnectionStatus = "Approved"
	PrivateEndpointServiceConnectionStatusPending  PrivateEndpointServiceConnectionStatus = "Pending"
	PrivateEndpointServiceConnectionStatusRejected PrivateEndpointServiceConnectionStatus = "Rejected"
)

// PossiblePrivateEndpointServiceConnectionStatusValues returns the possible values for the PrivateEndpointServiceConnectionStatus const type.
func PossiblePrivateEndpointServiceConnectionStatusValues() []PrivateEndpointServiceConnectionStatus {
	return []PrivateEndpointServiceConnectionStatus{
		PrivateEndpointServiceConnectionStatusApproved,
		PrivateEndpointServiceConnectionStatusPending,
		PrivateEndpointServiceConnectionStatusRejected,
	}
}

// ToPtr returns a *PrivateEndpointServiceConnectionStatus pointing to the current value.
func (c PrivateEndpointServiceConnectionStatus) ToPtr() *PrivateEndpointServiceConnectionStatus {
	return &c
}

// ProvisioningState - Provisioning state of the Video Analyzer account.
type ProvisioningState string

const (
	// ProvisioningStateFailed - Provisioning state failed.
	ProvisioningStateFailed ProvisioningState = "Failed"
	// ProvisioningStateInProgress - Provisioning state in progress.
	ProvisioningStateInProgress ProvisioningState = "InProgress"
	// ProvisioningStateSucceeded - Provisioning state succeeded.
	ProvisioningStateSucceeded ProvisioningState = "Succeeded"
)

// PossibleProvisioningStateValues returns the possible values for the ProvisioningState const type.
func PossibleProvisioningStateValues() []ProvisioningState {
	return []ProvisioningState{
		ProvisioningStateFailed,
		ProvisioningStateInProgress,
		ProvisioningStateSucceeded,
	}
}

// ToPtr returns a *ProvisioningState pointing to the current value.
func (c ProvisioningState) ToPtr() *ProvisioningState {
	return &c
}

// PublicNetworkAccess - Whether or not public network access is allowed for resources under the Video Analyzer account.
type PublicNetworkAccess string

const (
	// PublicNetworkAccessDisabled - Public network access is disabled.
	PublicNetworkAccessDisabled PublicNetworkAccess = "Disabled"
	// PublicNetworkAccessEnabled - Public network access is enabled.
	PublicNetworkAccessEnabled PublicNetworkAccess = "Enabled"
)

// PossiblePublicNetworkAccessValues returns the possible values for the PublicNetworkAccess const type.
func PossiblePublicNetworkAccessValues() []PublicNetworkAccess {
	return []PublicNetworkAccess{
		PublicNetworkAccessDisabled,
		PublicNetworkAccessEnabled,
	}
}

// ToPtr returns a *PublicNetworkAccess pointing to the current value.
func (c PublicNetworkAccess) ToPtr() *PublicNetworkAccess {
	return &c
}

// RtspTransport - Network transport utilized by the RTSP and RTP exchange: TCP or HTTP. When using TCP, the RTP packets are
// interleaved on the TCP RTSP connection. When using HTTP, the RTSP messages are exchanged
// through long lived HTTP connections, and the RTP packages are interleaved in the HTTP connections alongside the RTSP messages.
type RtspTransport string

const (
	// RtspTransportHTTP - HTTP transport. RTSP messages are exchanged over long running HTTP requests and RTP packets are interleaved
	// within the HTTP channel.
	RtspTransportHTTP RtspTransport = "Http"
	// RtspTransportTCP - TCP transport. RTSP is used directly over TCP and RTP packets are interleaved within the TCP channel.
	RtspTransportTCP RtspTransport = "Tcp"
)

// PossibleRtspTransportValues returns the possible values for the RtspTransport const type.
func PossibleRtspTransportValues() []RtspTransport {
	return []RtspTransport{
		RtspTransportHTTP,
		RtspTransportTCP,
	}
}

// ToPtr returns a *RtspTransport pointing to the current value.
func (c RtspTransport) ToPtr() *RtspTransport {
	return &c
}

// SKUName - The SKU name.
type SKUName string

const (
	// SKUNameBatchS1 - Represents the Batch S1 SKU name. Using this SKU you can create pipeline jobs to process recorded content.
	SKUNameBatchS1 SKUName = "Batch_S1"
	// SKUNameLiveS1 - Represents the Live S1 SKU name. Using this SKU you can create live pipelines to capture, record, and stream
	// live video from RTSP-capable cameras at bitrate settings from 0.5 Kbps to 3000 Kbps.
	SKUNameLiveS1 SKUName = "Live_S1"
)

// PossibleSKUNameValues returns the possible values for the SKUName const type.
func PossibleSKUNameValues() []SKUName {
	return []SKUName{
		SKUNameBatchS1,
		SKUNameLiveS1,
	}
}

// ToPtr returns a *SKUName pointing to the current value.
func (c SKUName) ToPtr() *SKUName {
	return &c
}

// SKUTier - The SKU tier.
type SKUTier string

const (
	// SKUTierStandard - Standard tier.
	SKUTierStandard SKUTier = "Standard"
)

// PossibleSKUTierValues returns the possible values for the SKUTier const type.
func PossibleSKUTierValues() []SKUTier {
	return []SKUTier{
		SKUTierStandard,
	}
}

// ToPtr returns a *SKUTier pointing to the current value.
func (c SKUTier) ToPtr() *SKUTier {
	return &c
}

// VideoAnalyzerEndpointType - The type of the endpoint.
type VideoAnalyzerEndpointType string

const (
	// VideoAnalyzerEndpointTypeClientAPI - The client API endpoint.
	VideoAnalyzerEndpointTypeClientAPI VideoAnalyzerEndpointType = "ClientApi"
)

// PossibleVideoAnalyzerEndpointTypeValues returns the possible values for the VideoAnalyzerEndpointType const type.
func PossibleVideoAnalyzerEndpointTypeValues() []VideoAnalyzerEndpointType {
	return []VideoAnalyzerEndpointType{
		VideoAnalyzerEndpointTypeClientAPI,
	}
}

// ToPtr returns a *VideoAnalyzerEndpointType pointing to the current value.
func (c VideoAnalyzerEndpointType) ToPtr() *VideoAnalyzerEndpointType {
	return &c
}

// VideoScaleMode - Describes the video scaling mode to be applied. Default mode is 'Pad'. If the mode is 'Pad' or 'Stretch'
// then both width and height must be specified. Else if the mode is 'PreserveAspectRatio' then
// only one of width or height need be provided.
type VideoScaleMode string

const (
	// VideoScaleModePad - Pads the video with black horizontal stripes (letterbox) or black vertical stripes (pillar-box) so
	// the video is resized to the specified dimensions while not altering the content aspect ratio.
	VideoScaleModePad VideoScaleMode = "Pad"
	// VideoScaleModePreserveAspectRatio - Preserves the same aspect ratio as the input video. If only one video dimension is
	// provided, the second dimension is calculated based on the input video aspect ratio. When 2 dimensions are provided, the
	// video is resized to fit the most constraining dimension, considering the input video size and aspect ratio.
	VideoScaleModePreserveAspectRatio VideoScaleMode = "PreserveAspectRatio"
	// VideoScaleModeStretch - Stretches the original video so it resized to the specified dimensions.
	VideoScaleModeStretch VideoScaleMode = "Stretch"
)

// PossibleVideoScaleModeValues returns the possible values for the VideoScaleMode const type.
func PossibleVideoScaleModeValues() []VideoScaleMode {
	return []VideoScaleMode{
		VideoScaleModePad,
		VideoScaleModePreserveAspectRatio,
		VideoScaleModeStretch,
	}
}

// ToPtr returns a *VideoScaleMode pointing to the current value.
func (c VideoScaleMode) ToPtr() *VideoScaleMode {
	return &c
}

// VideoType - Video content type. Different content types are suitable for different applications and scenarios.
type VideoType string

const (
	// VideoTypeArchive - Archive is flexible format that represents a video stream associated with wall-clock time. The video
	// archive can either be continuous or discontinuous. An archive is discontinuous when there are gaps in the recording due
	// to various reasons, such as the live pipeline being stopped, camera being disconnected or due to the use of event based
	// recordings through the use of a signal gate. There is no limit to the archive duration and new video data can be appended
	// to the existing archive at any time, as long as the same video codec and codec parameters are being used. Videos of this
	// type are suitable for appending and long term archival.
	VideoTypeArchive VideoType = "Archive"
	// VideoTypeFile - File represents a video which is stored as a single media file, such as MP4. Videos of this type are suitable
	// to be downloaded for external consumption.
	VideoTypeFile VideoType = "File"
)

// PossibleVideoTypeValues returns the possible values for the VideoType const type.
func PossibleVideoTypeValues() []VideoType {
	return []VideoType{
		VideoTypeArchive,
		VideoTypeFile,
	}
}

// ToPtr returns a *VideoType pointing to the current value.
func (c VideoType) ToPtr() *VideoType {
	return &c
}
