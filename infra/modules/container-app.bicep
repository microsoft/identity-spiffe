param name string
param location string
param tags object
param environmentId string
param registryServer string
param projectEndpoint string
param agentRole string
param acrResourceId string
param a2ResourceEndpoint string = ''

// User-assigned managed identity — created BEFORE the Container App
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${name}-identity'
  location: location
  tags: tags
}

// AcrPull role on the identity — also BEFORE the Container App
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

// Container App — depends on identity + role
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
        targetPort: 8000
        transport: 'auto'
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
          name: name
          image: 'mcr.microsoft.com/k8se/quickstart:latest'
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: concat([
            { name: 'PROJECT_ENDPOINT', value: projectEndpoint }
            { name: 'MODEL_DEPLOYMENT_NAME', value: 'gpt-4o-mini' }
            { name: 'AGENT_ROLE', value: agentRole }
            { name: 'AGENT_NAME', value: name }
          ], !empty(a2ResourceEndpoint) ? [
            { name: 'BACKEND_ENDPOINT', value: a2ResourceEndpoint }
            { name: 'A2_RESOURCE_ENDPOINT', value: a2ResourceEndpoint }  // deprecated
          ] : [])
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

output fqdn string = 'https://${containerApp.properties.configuration.ingress.fqdn}'
output name string = containerApp.name
output identityId string = identity.id
output identityPrincipalId string = identity.properties.principalId
