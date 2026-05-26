using './main.bicep'

param environmentName = readEnvironmentVariable('AZURE_ENV_NAME', 'aim-poc')
param location = 'westus'

// Phase 2: MSI attestation — no tokens needed!
param spiffeProxyImage = readEnvironmentVariable('SPIFFE_PROXY_IMAGE', 'mcr.microsoft.com/k8se/quickstart:latest')
param azureTenantId = readEnvironmentVariable('AZURE_TENANT_ID', '')

// SSH public key for SPIRE Server VM — password auth is disabled, SSH port is blocked by NSG.
// Reuses the existing adminSshPublicKey from azd env (set during initial provisioning).
param spireServerSshPublicKey = readEnvironmentVariable('adminSshPublicKey', '')

// Cross-cloud VPN (Phase 0) — set GCP_VPN_PUBLIC_IP and VPN_SHARED_KEY in azd env to deploy
param gcpVpnPublicIp = readEnvironmentVariable('GCP_VPN_PUBLIC_IP', '')
param gcpVpcCidr = readEnvironmentVariable('GCP_VPC_CIDR', '10.128.0.0/20')
param vpnSharedKey = readEnvironmentVariable('VPN_SHARED_KEY', '')

// GitHub Actions self-hosted runner (deploy.sh --github)
param deployGitHubRunner = readEnvironmentVariable('DEPLOY_GITHUB_RUNNER', 'false') == 'true' ? true : false
param githubOrg = readEnvironmentVariable('GITHUB_ORG', 'microsoft')
param githubRepo = readEnvironmentVariable('GITHUB_REPO', 'identity-spiffe')
