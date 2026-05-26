param location string
param tags object
param environmentName string
param resourceToken string
param logAnalyticsWorkspaceId string

var portalPolicyStorageAccountName = 'stacct${resourceToken}'
var portalPolicyConfigContainerName = 'portal-policy-configs'
var portalPolicyConfigBlobName = 'policy-configs.json'
var externalAgentStoreContainerName = 'portal-external-agents'
var externalAgentStoreBlobName = 'external-agents.json'

resource portalPolicyStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: portalPolicyStorageAccountName
  location: location
  tags: union(tags, { 'azd-service-name': 'portal-policy-store' })
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
  }
}

resource portalPolicyBlobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: portalPolicyStorage
  name: 'default'
}

resource portalPolicyContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: portalPolicyBlobService
  name: portalPolicyConfigContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource externalAgentStoreContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: portalPolicyBlobService
  name: externalAgentStoreContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource portalAppInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'appi-${environmentName}'
  location: location
  tags: union(tags, { 'azd-service-name': 'portal-observability' })
  kind: 'web'
  properties: {
    Application_Type: 'web'
    Flow_Type: 'Bluefield'
    Request_Source: 'rest'
    WorkspaceResourceId: logAnalyticsWorkspaceId
  }
}

output applicationInsightsConnectionString string = portalAppInsights.properties.ConnectionString
output policyStoreAccountUrl string = portalPolicyStorage.properties.primaryEndpoints.blob
output policyStoreBlobName string = portalPolicyConfigBlobName
output policyStoreContainer string = portalPolicyConfigContainerName
output policyStoreStorageAccountName string = portalPolicyStorage.name
output externalAgentStoreContainer string = externalAgentStoreContainerName
output externalAgentStoreBlobName string = externalAgentStoreBlobName
