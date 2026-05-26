// =============================================================================
// SPIRE Server Container App (MSI Attestation)
// =============================================================================
// Deploys SPIRE Server as a standalone Container App with internal-only ingress.
// Other SPIRE Agents connect to this server over the Container Apps Environment
// internal DNS at port 8081.
//
// The server validates MSI tokens from agent nodes using the azure_msi
// NodeAttestor. It needs the Azure tenant ID to know which tenants to trust.
// =============================================================================

param name string
param location string
param tags object
param environmentId string
param registryServer string
param acrResourceId string
param containerImage string = 'mcr.microsoft.com/k8se/quickstart:latest'
param azureTenantId string

// User-assigned managed identity for ACR pull
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${name}-identity'
  location: location
  tags: tags
}

var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

resource acrPullRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acrResourceId, identity.id, acrPullRoleId)
  scope: acrResource
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource acrResource 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: split(registryServer, '.')[0]
}

resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: name
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  dependsOn: [acrPullRole]
  properties: {
    managedEnvironmentId: environmentId
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: false  // Internal only — agents connect via environment DNS
        targetPort: 8081
        exposedPort: 8081
        transport: 'tcp'
      }
      registries: [
        {
          server: registryServer
          identity: identity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'spire-server'
          image: containerImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'CONTAINER_MODE', value: 'server' }
            { name: 'AZURE_TENANT_ID', value: azureTenantId }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

output fqdn string = containerApp.properties.configuration.ingress.fqdn
output name string = containerApp.name
