// =============================================================================
// Portal Container App (no SPIFFE sidecar)
// =============================================================================
// Deploys a portal web application as a single-container Container App with
// external ingress. Used for AIM Management Portal and CrowdStrike Mock Portal.
//
// Unlike container-app-phase2.bicep, this module:
//   - Has NO spiffe-proxy sidecar (portals don't need mTLS)
//   - Uses HTTP transport (not TCP)
//   - Accepts arbitrary environment variables + secrets
// =============================================================================

param name string
param location string
param tags object
param environmentId string
param registryServer string
param acrResourceId string
param containerImage string = 'mcr.microsoft.com/k8se/quickstart:latest'
param targetPort int
param envVars array = []
param secrets array = []
var effectiveEnvVars = concat(envVars, [
  {
    name: 'AZURE_CLIENT_ID'
    value: identity.properties.clientId
  }
])

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
        external: true
        targetPort: targetPort
        transport: 'auto'
      }
      registries: [
        {
          server: registryServer
          identity: identity.id
        }
      ]
      secrets: [for secret in secrets: {
        name: secret.name
        value: secret.value
      }]
    }
    template: {
      containers: [
        {
          name: name
          image: containerImage
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: effectiveEnvVars
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
output identityClientId string = identity.properties.clientId
output identityPrincipalId string = identity.properties.principalId
output identityResourceId string = identity.id
