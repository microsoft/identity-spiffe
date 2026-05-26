// =============================================================================
// Phase 2 Container App with SPIFFE Proxy Sidecar (MSI Attestation)
// =============================================================================
// Deploys an agent Container App with a spiffe-proxy sidecar that handles
// mTLS authentication via SPIRE.
//
// MSI Attestation: No join tokens needed. The sidecar's managed identity
// presents an MSI token to the SPIRE Server, which validates it against
// Azure AD. The agent SPIFFE ID is derived from tenant + principal ID:
//   spiffe://aim.microsoft.com/spire/agent/azure_msi/<tenant>/<principal>
//
// Workload registration entries map these agent SPIFFE IDs to workload
// SPIFFE IDs like spiffe://aim.microsoft.com/ests/bp/<bp-oid>/aid/<agent-oid>.
// =============================================================================

param name string
param location string
param tags object
param environmentId string
param registryServer string
param projectEndpoint string
param agentRole string
param acrResourceId string
param a2ResourceEndpoint string = ''

// Phase 2 SPIFFE parameters (MSI-based — no tokens!)
param proxyMode string            // 'egress' or 'ingress'
param spireServerFqdn string      // Internal app name of SPIRE server Container App
param allowedCallerSpiffeIds string = ''  // Comma-separated, for ingress mode
param remoteProxyAddr string = ''         // For egress mode: A2's ingress proxy address
param allowedRemoteSpiffeId string = ''   // For egress mode: A2's SPIFFE ID
param sidecarImage string = 'mcr.microsoft.com/k8se/quickstart:latest'

// User-assigned managed identity (used for ACR pull AND MSI attestation)
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

// ---- Sidecar environment variables (NO TOKEN!) ----
var egressEnv = [
  { name: 'CONTAINER_MODE', value: 'agent-proxy' }
  { name: 'PROXY_MODE', value: 'egress' }
  { name: 'SPIRE_SERVER_ADDR', value: spireServerFqdn }
  { name: 'HTTP_LISTEN_ADDR', value: ':8080' }
  { name: 'REMOTE_PROXY_ADDR', value: remoteProxyAddr }
  { name: 'ALLOWED_REMOTE_SPIFFE_ID', value: allowedRemoteSpiffeId }
]

var ingressEnv = [
  { name: 'CONTAINER_MODE', value: 'agent-proxy' }
  { name: 'PROXY_MODE', value: 'ingress' }
  { name: 'SPIRE_SERVER_ADDR', value: spireServerFqdn }
  { name: 'GRPC_LISTEN_ADDR', value: ':8443' }
  { name: 'APP_ADDR', value: 'localhost:8000' }
  { name: 'ALLOWED_CALLER_SPIFFE_IDS', value: allowedCallerSpiffeIds }
  { name: 'RBAC_POLICY_PATH', value: '/app/config/spiffe-rbac-policy.yaml' }
]

var sidecarEnv = proxyMode == 'egress' ? egressEnv : ingressEnv

// ---- Agent environment variables ----
var callerAgentEnv = [
  { name: 'PROJECT_ENDPOINT', value: projectEndpoint }
  { name: 'MODEL_DEPLOYMENT_NAME', value: 'gpt-4o-mini' }
  { name: 'AGENT_ROLE', value: agentRole }
  { name: 'AGENT_NAME', value: name }
  { name: 'BACKEND_ENDPOINT', value: 'http://localhost:8080' }
  { name: 'A2_RESOURCE_ENDPOINT', value: 'http://localhost:8080' }  // deprecated, kept for compat
]

var resourceAgentEnv = [
  { name: 'PROJECT_ENDPOINT', value: projectEndpoint }
  { name: 'MODEL_DEPLOYMENT_NAME', value: 'gpt-4o-mini' }
  { name: 'AGENT_ROLE', value: agentRole }
  { name: 'AGENT_NAME', value: name }
]

var agentEnv = proxyMode == 'egress' ? callerAgentEnv : resourceAgentEnv

// ---- Ingress configuration ----
var ingressConfig = proxyMode == 'ingress' ? {
  external: false
  targetPort: 8443
  exposedPort: 8443
  transport: 'tcp'
} : {
  external: true
  targetPort: 8000
  transport: 'auto'
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
      ingress: ingressConfig
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
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: agentEnv
        }
        {
          name: '${name}-spiffe-proxy'
          image: sidecarImage
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: sidecarEnv
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
output identityId string = identity.id
output identityPrincipalId string = identity.properties.principalId
output identityClientId string = identity.properties.clientId
