targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name of the environment (used for resource naming)')
param environmentName string

@description('Primary location for all resources')
param location string = 'westus'

// Phase 2 MSI attestation — no tokens needed!
// The SPIFFE proxy sidecar image (placeholder until built)
param spiffeProxyImage string = 'mcr.microsoft.com/k8se/quickstart:latest'

// Azure tenant ID for SPIRE Server's azure_msi NodeAttestor.
// deploy.sh writes this from the signed-in azd environment.
param azureTenantId string = ''

// SSH public key for SPIRE Server VM (password auth is disabled).
// SSH access is blocked by NSG — this only satisfies the ARM API requirement.
// Default '' allows azd provision to succeed; VM module handles the empty case.
param spireServerSshPublicKey string = ''

@description('GCP VPN gateway public IP. When provided, deploys Azure VPN Gateway for cross-cloud connectivity.')
param gcpVpnPublicIp string = ''

@description('GCP VPC CIDR range to route through VPN tunnel.')
param gcpVpcCidr string = '10.128.0.0/20'

@secure()
@description('IPsec shared key for VPN tunnel. Required when gcpVpnPublicIp is set.')
param vpnSharedKey string = ''

@description('Deploy GitHub Actions self-hosted runner VM. Set to true with --github flag.')
param deployGitHubRunner bool = false

@description('GitHub organization name for runner registration.')
param githubOrg string = 'microsoft'

@description('GitHub repository for runner registration.')
param githubRepo string = 'identity-spiffe'

var tags = {
  'azd-env-name': environmentName
  project: 'isp-prototype-platform'
  team: 'identity-spiffe'
  phase: 'phase2-msi'
}

var abbrs = loadJsonContent('./abbreviations.json')
var resourceToken = toLower(uniqueString(subscription().id, environmentName, location))

// Trust domain for SPIFFE IDs
var trustDomain = 'aim.microsoft.com'

resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: 'rg-${environmentName}'
  location: location
  tags: tags
}

// =============================================================================
// Shared infrastructure
// =============================================================================

module acr 'modules/acr.bicep' = {
  name: 'acr'
  scope: rg
  params: {
    name: '${abbrs.containerRegistryRegistries}${resourceToken}'
    location: location
    tags: tags
  }
}

// ⚠️ VNet integration: first deploy to existing environments recreates ACA
// environment and redeploys SPIRE VM (subnet change). Use --new for fresh
// environments. Orphaned spire-server-vnet/nsg resources require manual cleanup.
module networking 'modules/networking.bicep' = {
  name: 'networking'
  scope: rg
  params: {
    name: '${abbrs.networkVirtualNetworks}${resourceToken}'
    location: location
    tags: tags
  }
}

module vpnGateway 'modules/vpn-gateway.bicep' = if (gcpVpnPublicIp != '') {
  name: 'vpn-gateway'
  scope: rg
  params: {
    name: 'isp-vpn-${resourceToken}'
    location: location
    tags: tags
    gatewaySubnetId: networking.outputs.gatewaySubnetId
    gcpVpnPublicIp: gcpVpnPublicIp
    gcpVpcCidr: gcpVpcCidr
    sharedKey: vpnSharedKey
  }
}

module containerAppsEnv 'modules/container-apps-env.bicep' = {
  name: 'containerAppsEnv'
  scope: rg
  params: {
    name: '${abbrs.appManagedEnvironments}${resourceToken}'
    location: location
    tags: tags
    infrastructureSubnetId: networking.outputs.acaSubnetId
  }
}

// =============================================================================
// Phase 2: SPIRE Server on VM (full IMDS)
// =============================================================================
// Neither Container Apps nor ACI expose IMDS metadata/instance, which the
// SPIRE Server's azure_msi NodeAttestor needs during plugin configuration.
// A VM is the only Azure compute with full IMDS support.
// =============================================================================
module spireServer 'modules/spire-server-vm.bicep' = {
  name: 'spire-server'
  scope: rg
  params: {
    name: 'spire-server'
    location: location
    tags: union(tags, { 'azd-service-name': 'spire-server' })
    registryServer: acr.outputs.loginServer
    acrResourceId: acr.outputs.id
    containerImage: spiffeProxyImage
    azureTenantId: azureTenantId
    sshPublicKey: spireServerSshPublicKey
    logAnalyticsWorkspaceId: containerAppsEnv.outputs.logAnalyticsWorkspaceId
    subnetId: networking.outputs.spireServerSubnetId
  }
}

// =============================================================================
// GitHub Actions Self-Hosted Runner VM (optional, --github flag)
// =============================================================================
module githubRunner 'modules/github-runner-vm.bicep' = if (deployGitHubRunner) {
  name: 'github-runner'
  scope: rg
  params: {
    name: 'github-runner'
    location: location
    tags: union(tags, { 'azd-service-name': 'github-runner' })
    azureTenantId: azureTenantId
    sshPublicKey: spireServerSshPublicKey
    subnetId: networking.outputs.spireServerSubnetId
    // spireServerPrivateIp uses module default (10.200.0.4) — spire-server-vm.bicep
    // doesn't expose a privateIpAddress output
    githubOrg: githubOrg
    githubRepo: githubRepo
  }
}

// =============================================================================
// Phase 2: A2 Resource with INGRESS proxy sidecar
// =============================================================================
module budgetBackend 'modules/container-app-phase2.bicep' = {
  name: 'budget-backend'
  scope: rg
  params: {
    name: 'budget-backend'
    location: location
    tags: union(tags, { 'azd-service-name': 'budget-backend' })
    environmentId: containerAppsEnv.outputs.environmentId
    registryServer: acr.outputs.loginServer
    projectEndpoint: ''
    agentRole: 'resource-mcp-server'
    acrResourceId: acr.outputs.id
    // Phase 2 SPIFFE params (MSI — no tokens!)
    proxyMode: 'ingress'
    spireServerFqdn: spireServer.outputs.fqdn
    allowedCallerSpiffeIds: 'spiffe://${trustDomain}/ests/bp/placeholder-bp-oid/aid/placeholder-report-oid,spiffe://${trustDomain}/ests/bp/placeholder-bp-oid/aid/placeholder-approval-oid'
    sidecarImage: spiffeProxyImage
  }
}

// =============================================================================
// Phase 2: Caller agents with EGRESS proxy sidecars
// =============================================================================

module budgetReport 'modules/container-app-phase2.bicep' = {
  name: 'budget-report'
  scope: rg
  params: {
    name: 'budget-report'
    location: location
    tags: union(tags, { 'azd-service-name': 'budget-report' })
    environmentId: containerAppsEnv.outputs.environmentId
    registryServer: acr.outputs.loginServer
    projectEndpoint: ''
    agentRole: 'caller-allowed'
    acrResourceId: acr.outputs.id
    a2ResourceEndpoint: 'https://${budgetBackend.outputs.fqdn}'
    // Phase 2 SPIFFE params (MSI — no tokens!)
    proxyMode: 'egress'
    spireServerFqdn: spireServer.outputs.fqdn
    remoteProxyAddr: 'budget-backend:8443'
    allowedRemoteSpiffeId: 'spiffe://${trustDomain}/ests/bp/placeholder-bp-oid/aid/placeholder-backend-oid'
    sidecarImage: spiffeProxyImage
  }
}

module employeeMenus 'modules/container-app-phase2.bicep' = {
  name: 'employee-menus'
  scope: rg
  params: {
    name: 'employee-menus'
    location: location
    tags: union(tags, { 'azd-service-name': 'employee-menus' })
    environmentId: containerAppsEnv.outputs.environmentId
    registryServer: acr.outputs.loginServer
    projectEndpoint: ''
    agentRole: 'caller-blocked'
    acrResourceId: acr.outputs.id
    a2ResourceEndpoint: 'https://${budgetBackend.outputs.fqdn}'
    // Phase 2 SPIFFE params (MSI — no tokens!)
    proxyMode: 'egress'
    spireServerFqdn: spireServer.outputs.fqdn
    remoteProxyAddr: 'budget-backend:8443'
    allowedRemoteSpiffeId: 'spiffe://${trustDomain}/ests/bp/placeholder-bp-oid/aid/placeholder-backend-oid'
    sidecarImage: spiffeProxyImage
  }
}

module budgetApproval 'modules/container-app-phase2.bicep' = {
  name: 'budget-approval'
  scope: rg
  params: {
    name: 'budget-approval'
    location: location
    tags: union(tags, { 'azd-service-name': 'budget-approval' })
    environmentId: containerAppsEnv.outputs.environmentId
    registryServer: acr.outputs.loginServer
    projectEndpoint: ''
    agentRole: 'caller-allowed'
    acrResourceId: acr.outputs.id
    a2ResourceEndpoint: 'https://${budgetBackend.outputs.fqdn}'
    // Phase 2 SPIFFE params (MSI — no tokens!)
    proxyMode: 'egress'
    spireServerFqdn: spireServer.outputs.fqdn
    remoteProxyAddr: 'budget-backend:8443'
    allowedRemoteSpiffeId: 'spiffe://${trustDomain}/ests/bp/placeholder-bp-oid/aid/placeholder-backend-oid'
    sidecarImage: spiffeProxyImage
  }
}

module adminControlPlane 'modules/container-app-phase2.bicep' = {
  name: 'admin-control-plane'
  scope: rg
  params: {
    name: 'admin-control-plane'
    location: location
    tags: union(tags, { 'azd-service-name': 'admin-control-plane' })
    environmentId: containerAppsEnv.outputs.environmentId
    registryServer: acr.outputs.loginServer
    projectEndpoint: ''
    agentRole: 'admin-control-plane'
    acrResourceId: acr.outputs.id
    a2ResourceEndpoint: 'https://${budgetBackend.outputs.fqdn}'
    proxyMode: 'egress'
    spireServerFqdn: spireServer.outputs.fqdn
    remoteProxyAddr: 'budget-backend:8443'
    allowedRemoteSpiffeId: 'spiffe://${trustDomain}/ests/bp/placeholder-bp-oid/aid/placeholder-backend-oid'
    sidecarImage: spiffeProxyImage
  }
}

// =============================================================================
// Portal web applications (no SPIFFE sidecar — these are admin UIs)
// =============================================================================

// Container images for portals (placeholder until built in deploy.sh)
param portalImage string = 'mcr.microsoft.com/k8se/quickstart:latest'
param securityportalMockImage string = 'mcr.microsoft.com/k8se/quickstart:latest'

// Auth configuration (populated by deploy.sh after Entra app registration)
param portalAuthClientId string = ''
param securityportalAuthClientId string = ''
param aimAdminGroupId string = ''
param aimViewerGroupId string = ''

// Graph API credentials for portal runtime (risk push, etc.)
// Defaults to 'placeholder' because Container App secrets reject empty values.
// deploy.sh overwrites these with real values after Entra provisioning.
@secure()
param graphClientId string = 'placeholder'
@secure()
param graphClientSecret string = 'placeholder'

// Management API key for portal → admin-control-plane communication
@secure()
param mgmtApiKey string = 'placeholder'

module portalSupport 'modules/portal-support.bicep' = {
  name: 'portal-support'
  scope: rg
  params: {
    location: location
    tags: tags
    environmentName: environmentName
    resourceToken: resourceToken
    logAnalyticsWorkspaceId: containerAppsEnv.outputs.logAnalyticsWorkspaceId
  }
}

module aimPortal 'modules/portal-app.bicep' = {
  name: 'isp-portal'
  scope: rg
  params: {
    name: 'isp-portal'
    location: location
    tags: union(tags, { 'azd-service-name': 'isp-portal' })
    environmentId: containerAppsEnv.outputs.environmentId
    registryServer: acr.outputs.loginServer
    acrResourceId: acr.outputs.id
    containerImage: portalImage
    targetPort: 8550
    secrets: [
      { name: 'mgmt-api-key', value: mgmtApiKey }
      { name: 'graph-client-id', value: graphClientId }
      { name: 'graph-client-secret', value: graphClientSecret }
    ]
    envVars: [
      { name: 'ADMIN_CP_URL', value: 'https://${adminControlPlane.outputs.fqdn}' }
      { name: 'MGMT_API_KEY', secretRef: 'mgmt-api-key' }
      { name: 'AZURE_TENANT_ID', value: azureTenantId }
      { name: 'AUTH_CLIENT_ID', value: portalAuthClientId }
      { name: 'ISP_ADMIN_GROUP_ID', value: aimAdminGroupId }
      { name: 'ISP_VIEWER_GROUP_ID', value: aimViewerGroupId }
      { name: 'GRAPH_CLIENT_ID', secretRef: 'graph-client-id' }
      { name: 'GRAPH_CLIENT_SECRET', secretRef: 'graph-client-secret' }
      { name: 'POLICY_CONFIG_STORE_PROVIDER', value: 'blob' }
      { name: 'POLICY_CONFIG_BLOB_ACCOUNT_URL', value: portalSupport.outputs.policyStoreAccountUrl }
      { name: 'POLICY_CONFIG_BLOB_CONTAINER', value: portalSupport.outputs.policyStoreContainer }
      { name: 'POLICY_CONFIG_BLOB_NAME', value: portalSupport.outputs.policyStoreBlobName }
      { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: portalSupport.outputs.applicationInsightsConnectionString }
      { name: 'PORTAL_MODE', value: 'cloud' }
    ]
  }
}

module aimPortalPolicyStoreAccess 'modules/portal-policy-store-access.bicep' = {
  name: 'isp-portal-policy-store-access'
  scope: rg
  params: {
    storageAccountName: portalSupport.outputs.policyStoreStorageAccountName
    principalId: aimPortal.outputs.identityPrincipalId
  }
}

module securityportalMock 'modules/portal-app.bicep' = {
  name: 'securityportal-mock'
  scope: rg
  params: {
    name: 'securityportal-mock'
    location: location
    tags: union(tags, { 'azd-service-name': 'securityportal-mock' })
    environmentId: containerAppsEnv.outputs.environmentId
    registryServer: acr.outputs.loginServer
    acrResourceId: acr.outputs.id
    containerImage: securityportalMockImage
    targetPort: 8560
    secrets: [
      { name: 'mgmt-api-key', value: mgmtApiKey }
      { name: 'graph-client-id', value: graphClientId }
      { name: 'graph-client-secret', value: graphClientSecret }
    ]
    envVars: [
      { name: 'ADMIN_CP_URL', value: 'https://${adminControlPlane.outputs.fqdn}' }
      { name: 'MGMT_API_KEY', secretRef: 'mgmt-api-key' }
      { name: 'AZURE_TENANT_ID', value: azureTenantId }
      { name: 'AUTH_CLIENT_ID', value: securityportalAuthClientId }
      { name: 'ISP_ADMIN_GROUP_ID', value: aimAdminGroupId }
      { name: 'ISP_VIEWER_GROUP_ID', value: aimViewerGroupId }
      { name: 'GRAPH_CLIENT_ID', secretRef: 'graph-client-id' }
      { name: 'GRAPH_CLIENT_SECRET', secretRef: 'graph-client-secret' }
      { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: portalSupport.outputs.applicationInsightsConnectionString }
      { name: 'PORTAL_MODE', value: 'cloud' }
    ]
  }
}

// =============================================================================
// Outputs
// =============================================================================
output AZURE_CONTAINER_REGISTRY_ENDPOINT string = acr.outputs.loginServer
output AZURE_RESOURCE_GROUP string = rg.name
output AZURE_TENANT_ID string = azureTenantId
output SPIRE_SERVER_FQDN string = spireServer.outputs.fqdn
output SPIRE_SERVER_IP string = spireServer.outputs.ipAddress
output SERVICE_BUDGET_REPORT_ENDPOINT_URL string = 'https://${budgetReport.outputs.fqdn}'
output SERVICE_BUDGET_BACKEND_ENDPOINT_URL string = 'https://${budgetBackend.outputs.fqdn}'
output SERVICE_EMPLOYEE_MENUS_ENDPOINT_URL string = 'https://${employeeMenus.outputs.fqdn}'
output SERVICE_BUDGET_APPROVAL_ENDPOINT_URL string = 'https://${budgetApproval.outputs.fqdn}'
output SERVICE_ADMIN_CONTROL_PLANE_ENDPOINT_URL string = 'https://${adminControlPlane.outputs.fqdn}'
output SERVICE_ISP_PORTAL_ENDPOINT_URL string = 'https://${aimPortal.outputs.fqdn}'
output SERVICE_SECURITYPORTAL_MOCK_ENDPOINT_URL string = 'https://${securityportalMock.outputs.fqdn}'
// Principal IDs for SPIRE registration (maps MSI identity → SPIFFE ID)
output BUDGET_REPORT_PRINCIPAL_ID string = budgetReport.outputs.identityPrincipalId
output BUDGET_BACKEND_PRINCIPAL_ID string = budgetBackend.outputs.identityPrincipalId
output EMPLOYEE_MENUS_PRINCIPAL_ID string = employeeMenus.outputs.identityPrincipalId
output BUDGET_APPROVAL_PRINCIPAL_ID string = budgetApproval.outputs.identityPrincipalId
output ADMIN_CONTROL_PLANE_PRINCIPAL_ID string = adminControlPlane.outputs.identityPrincipalId
output VNET_ID string = networking.outputs.vnetId
output GATEWAY_SUBNET_ID string = networking.outputs.gatewaySubnetId
output VPN_GATEWAY_PUBLIC_IP string = gcpVpnPublicIp != '' ? vpnGateway.outputs.gatewayPublicIp : ''
