param storageAccountName string
param principalId string

var storageBlobDataContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'

resource portalPolicyStorage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = {
  name: storageAccountName
}

resource portalPolicyStoreRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(portalPolicyStorage.id, principalId, storageBlobDataContributorRoleId)
  scope: portalPolicyStorage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataContributorRoleId)
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}
