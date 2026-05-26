// =============================================================================
// GitHub Actions Self-Hosted Runner VM
// =============================================================================
// Provisions an Azure VM in the shared VNet for GitHub Actions self-hosted runner
// with SPIRE agent + spiffe-proxy egress. Cloud-init bootstraps the runner.
// No VPN needed — same VNet as SPIRE server and Container Apps.
// =============================================================================

@description('VM resource name')
param name string

@description('Azure region')
param location string

@description('Resource tags')
param tags object = {}

@description('SSH public key for VM access (empty = password auth disabled)')
param sshPublicKey string = ''

@description('Subnet ID for the VM NIC')
param subnetId string

@description('Azure tenant ID')
param azureTenantId string

@description('SPIRE server private IP for agent enrollment')
param spireServerPrivateIp string = '10.200.0.4'

@description('GitHub organization name')
param githubOrg string = 'microsoft'

@description('GitHub repository for runner registration')
param githubRepo string = 'identity-spiffe'

// ─── NSG ─────────────────────────────────────────────────────────────────────
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: '${name}-nsg'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowSSH-AzureOnly'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'AzureCloud'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
    ]
  }
}

// ─── Public IP ───────────────────────────────────────────────────────────────
resource publicIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: '${name}-pip'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

// ─── NIC ─────────────────────────────────────────────────────────────────────
resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: '${name}-nic'
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: subnetId }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: { id: publicIp.id }
        }
      }
    ]
    networkSecurityGroup: { id: nsg.id }
  }
}

// ─── Cloud-init ──────────────────────────────────────────────────────────────
var cloudInit = '''
#!/bin/bash
set -euo pipefail
exec > /var/log/github-runner-setup.log 2>&1

echo "=== GitHub Runner VM cloud-init ==="
echo "Tenant: __TENANT_ID__"
echo "SPIRE Server: __SPIRE_SERVER_IP__"
echo "GitHub Org: __GITHUB_ORG__"
echo "GitHub Repo: __GITHUB_REPO__"

# Install prerequisites
apt-get update -y
apt-get install -y curl jq docker.io

# The actual setup is done by scripts/setup-github-runner.sh
# which is copied to the VM and run by deploy.sh --github
echo "=== Cloud-init complete. Waiting for setup-github-runner.sh ==="
'''

var cloudInitResolved = replace(
  replace(
    replace(
      replace(cloudInit, '__TENANT_ID__', azureTenantId),
      '__SPIRE_SERVER_IP__', spireServerPrivateIp),
    '__GITHUB_ORG__', githubOrg),
  '__GITHUB_REPO__', githubRepo)

// ─── VM ──────────────────────────────────────────────────────────────────────
resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    hardwareProfile: { vmSize: 'Standard_B2s' }
    osProfile: {
      computerName: name
      adminUsername: 'azureuser'
      customData: base64(cloudInitResolved)
      linuxConfiguration: {
        disablePasswordAuthentication: sshPublicKey != '' ? true : false
        ssh: sshPublicKey != '' ? {
          publicKeys: [
            {
              path: '/home/azureuser/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        } : null
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-jammy'
        sku: '22_04-lts-gen2'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'StandardSSD_LRS' }
        diskSizeGB: 64
      }
    }
    networkProfile: {
      networkInterfaces: [{ id: nic.id }]
    }
  }
}

// ─── Outputs ─────────────────────────────────────────────────────────────────
output vmId string = vm.id
output vmName string = vm.name
output publicIpAddress string = publicIp.properties.ipAddress
output privateIpAddress string = nic.properties.ipConfigurations[0].properties.privateIPAddress
