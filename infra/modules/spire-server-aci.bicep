// =============================================================================
// SPIRE Server on Azure Container Instances (ACI)
// =============================================================================
// Deploys SPIRE Server as an ACI container group instead of Container Apps.
//
// WHY ACI instead of Container Apps?
// Container Apps only exposes the IMDS token endpoint (metadata/identity/oauth2/token).
// The SPIRE Server's azure_msi NodeAttestor plugin calls metadata/instance during
// Configure() to discover the Azure environment (cloud type, JWKS endpoint).
// That endpoint is NOT available on Container Apps, causing a fatal timeout.
// ACI runs on real VMs where full IMDS is available.
//
// Networking: Exposes port 8081 with a public FQDN. SPIRE Agents on Container Apps
// connect to this FQDN. SPIRE's own TLS protects the connection.
// For production: use VNet integration to keep this internal.
// =============================================================================

param name string
param location string
param tags object
param registryServer string
param acrResourceId string
param containerImage string = 'mcr.microsoft.com/k8se/quickstart:latest'
param azureTenantId string

// User-assigned managed identity for ACR pull + IMDS availability
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${name}-identity'
  location: location
  tags: tags
}

var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

resource acrResource 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: split(registryServer, '.')[0]
}

resource acrPullRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acrResourceId, identity.id, acrPullRoleId)
  scope: acrResource
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// DNS name label for the public FQDN
var dnsLabel = '${name}-${uniqueString(resourceGroup().id)}'

resource containerGroup 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
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
    osType: 'Linux'
    restartPolicy: 'Always'
    ipAddress: {
      type: 'Public'
      ports: [
        {
          port: 8081
          protocol: 'TCP'
        }
      ]
      dnsNameLabel: dnsLabel
    }
    imageRegistryCredentials: [
      {
        server: registryServer
        identity: identity.id
      }
    ]
    containers: [
      {
        name: 'spire-server'
        properties: {
          image: containerImage
          resources: {
            requests: {
              cpu: 1
              memoryInGB: 2
            }
          }
          ports: [
            {
              port: 8081
              protocol: 'TCP'
            }
          ]
          environmentVariables: [
            { name: 'CONTAINER_MODE', value: 'server' }
            { name: 'AZURE_TENANT_ID', value: azureTenantId }
          ]
          // No special security context needed — IMDS mock binds to
          // 169.254.169.254 via ip addr add on loopback (no privileges required)
        }
      }
    ]
  }
}

output fqdn string = containerGroup.properties.ipAddress.fqdn
output ipAddress string = containerGroup.properties.ipAddress.ip
output name string = containerGroup.name
output identityPrincipalId string = identity.properties.principalId
