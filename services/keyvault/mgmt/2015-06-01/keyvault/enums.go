package keyvault

// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

// CertificatePermissions enumerates the values for certificate permissions.
type CertificatePermissions string

const (
	// All ...
	All CertificatePermissions = "all"
	// Create ...
	Create CertificatePermissions = "create"
	// Delete ...
	Delete CertificatePermissions = "delete"
	// Deleteissuers ...
	Deleteissuers CertificatePermissions = "deleteissuers"
	// Get ...
	Get CertificatePermissions = "get"
	// Getissuers ...
	Getissuers CertificatePermissions = "getissuers"
	// Import ...
	Import CertificatePermissions = "import"
	// List ...
	List CertificatePermissions = "list"
	// Listissuers ...
	Listissuers CertificatePermissions = "listissuers"
	// Managecontacts ...
	Managecontacts CertificatePermissions = "managecontacts"
	// Manageissuers ...
	Manageissuers CertificatePermissions = "manageissuers"
	// Purge ...
	Purge CertificatePermissions = "purge"
	// Recover ...
	Recover CertificatePermissions = "recover"
	// Setissuers ...
	Setissuers CertificatePermissions = "setissuers"
	// Update ...
	Update CertificatePermissions = "update"
)

// PossibleCertificatePermissionsValues returns an array of possible values for the CertificatePermissions const type.
func PossibleCertificatePermissionsValues() []CertificatePermissions {
	return []CertificatePermissions{All, Create, Delete, Deleteissuers, Get, Getissuers, Import, List, Listissuers, Managecontacts, Manageissuers, Purge, Recover, Setissuers, Update}
}

// KeyPermissions enumerates the values for key permissions.
type KeyPermissions string

const (
	// KeyPermissionsAll ...
	KeyPermissionsAll KeyPermissions = "all"
	// KeyPermissionsBackup ...
	KeyPermissionsBackup KeyPermissions = "backup"
	// KeyPermissionsCreate ...
	KeyPermissionsCreate KeyPermissions = "create"
	// KeyPermissionsDecrypt ...
	KeyPermissionsDecrypt KeyPermissions = "decrypt"
	// KeyPermissionsDelete ...
	KeyPermissionsDelete KeyPermissions = "delete"
	// KeyPermissionsEncrypt ...
	KeyPermissionsEncrypt KeyPermissions = "encrypt"
	// KeyPermissionsGet ...
	KeyPermissionsGet KeyPermissions = "get"
	// KeyPermissionsImport ...
	KeyPermissionsImport KeyPermissions = "import"
	// KeyPermissionsList ...
	KeyPermissionsList KeyPermissions = "list"
	// KeyPermissionsPurge ...
	KeyPermissionsPurge KeyPermissions = "purge"
	// KeyPermissionsRecover ...
	KeyPermissionsRecover KeyPermissions = "recover"
	// KeyPermissionsRestore ...
	KeyPermissionsRestore KeyPermissions = "restore"
	// KeyPermissionsSign ...
	KeyPermissionsSign KeyPermissions = "sign"
	// KeyPermissionsUnwrapKey ...
	KeyPermissionsUnwrapKey KeyPermissions = "unwrapKey"
	// KeyPermissionsUpdate ...
	KeyPermissionsUpdate KeyPermissions = "update"
	// KeyPermissionsVerify ...
	KeyPermissionsVerify KeyPermissions = "verify"
	// KeyPermissionsWrapKey ...
	KeyPermissionsWrapKey KeyPermissions = "wrapKey"
)

// PossibleKeyPermissionsValues returns an array of possible values for the KeyPermissions const type.
func PossibleKeyPermissionsValues() []KeyPermissions {
	return []KeyPermissions{KeyPermissionsAll, KeyPermissionsBackup, KeyPermissionsCreate, KeyPermissionsDecrypt, KeyPermissionsDelete, KeyPermissionsEncrypt, KeyPermissionsGet, KeyPermissionsImport, KeyPermissionsList, KeyPermissionsPurge, KeyPermissionsRecover, KeyPermissionsRestore, KeyPermissionsSign, KeyPermissionsUnwrapKey, KeyPermissionsUpdate, KeyPermissionsVerify, KeyPermissionsWrapKey}
}

// SecretPermissions enumerates the values for secret permissions.
type SecretPermissions string

const (
	// SecretPermissionsAll ...
	SecretPermissionsAll SecretPermissions = "all"
	// SecretPermissionsBackup ...
	SecretPermissionsBackup SecretPermissions = "backup"
	// SecretPermissionsDelete ...
	SecretPermissionsDelete SecretPermissions = "delete"
	// SecretPermissionsGet ...
	SecretPermissionsGet SecretPermissions = "get"
	// SecretPermissionsList ...
	SecretPermissionsList SecretPermissions = "list"
	// SecretPermissionsPurge ...
	SecretPermissionsPurge SecretPermissions = "purge"
	// SecretPermissionsRecover ...
	SecretPermissionsRecover SecretPermissions = "recover"
	// SecretPermissionsRestore ...
	SecretPermissionsRestore SecretPermissions = "restore"
	// SecretPermissionsSet ...
	SecretPermissionsSet SecretPermissions = "set"
)

// PossibleSecretPermissionsValues returns an array of possible values for the SecretPermissions const type.
func PossibleSecretPermissionsValues() []SecretPermissions {
	return []SecretPermissions{SecretPermissionsAll, SecretPermissionsBackup, SecretPermissionsDelete, SecretPermissionsGet, SecretPermissionsList, SecretPermissionsPurge, SecretPermissionsRecover, SecretPermissionsRestore, SecretPermissionsSet}
}

// SkuName enumerates the values for sku name.
type SkuName string

const (
	// Premium ...
	Premium SkuName = "premium"
	// Standard ...
	Standard SkuName = "standard"
)

// PossibleSkuNameValues returns an array of possible values for the SkuName const type.
func PossibleSkuNameValues() []SkuName {
	return []SkuName{Premium, Standard}
}