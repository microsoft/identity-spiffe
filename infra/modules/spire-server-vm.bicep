// =============================================================================
// SPIRE Server on Azure VM
// =============================================================================
// Deploys SPIRE Server as a Docker container on a small Linux VM.
//
// WHY a VM instead of Container Apps or ACI?
// The SPIRE Server's azure_msi NodeAttestor plugin calls IMDS metadata/instance
// during Configure() to discover the Azure cloud environment. Neither Container
// Apps nor ACI expose this endpoint — only VMs have full IMDS.
//
// This is a Standard_B2s (2 vCPU, 4GB RAM). B1s (1 vCPU, 1GB) was too small —
// cloud-init + Docker pull + SPIRE server starved SSH, causing deploy timeouts.
// Cloud-init pulls the container image from ACR and runs it with explicit port
// mapping (-p 8081:8081) instead of --network host to reduce attack surface.
//
// Networking: Public IP with NSG allowing inbound TCP 8081 from AzureCloud and
// SSH (port 22) for deploy.sh VM operations. SSH replaces `az vm run-command`
// which had fatal single-slot/guest-agent bottlenecks (see hard-won-learnings.md).
// For production: use VNet integration + private endpoint.
// =============================================================================

param name string
param location string
param tags object
param registryServer string
param acrResourceId string
param containerImage string = 'mcr.microsoft.com/k8se/quickstart:latest'
param azureTenantId string

@description('SSH public key for VM admin user. SSH access is blocked by NSG; this satisfies the ARM API requirement when password auth is disabled. Empty string falls back to password auth.')
param sshPublicKey string = ''

@description('Log Analytics workspace resource ID for SPIRE server log shipping. Empty disables monitoring.')
param logAnalyticsWorkspaceId string = ''

@description('External subnet resource ID for the SPIRE VM NIC. When provided, the module skips creating its own VNet/subnet/NSG and uses the shared subnet instead. Leave empty to create standalone networking (backwards compatible).')
param subnetId string = ''

// User-assigned managed identity for ACR pull + IMDS
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

// Networking
var dnsLabel = '${name}-${uniqueString(resourceGroup().id)}'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = if (subnetId == '') {
  name: '${name}-nsg'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowSPIREInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '8081'
          // TODO: Restrict to VNet once Container Apps are VNet-integrated.
          // Currently Container Apps use Azure-managed outbound IPs (not in
          // this VNet), so 'VirtualNetwork' tag would block agent attestation.
          // For production: VNet-integrate Container Apps + use private endpoint.
          sourceAddressPrefix: 'AzureCloud'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'AllowSSHInbound'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          // Restrict SSH to AzureCloud source IP ranges rather than internet-wide
          // access. deploy.sh uses 'az vm run-command' for automated VM operations
          // (no inbound SSH required). This SSH rule is retained for manual
          // debugging/troubleshooting access from Azure-hosted workstations.
          // Note: 'AzureCloud' includes all Azure datacenter IP ranges and is not
          // true internal-only access. For stricter access, use 'VirtualNetwork',
          // a dedicated bastion subnet, or explicit CIDR allowlists.
          sourceAddressPrefix: 'AzureCloud'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = if (subnetId == '') {
  name: '${name}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: ['10.200.0.0/16']
    }
    subnets: [
      {
        name: 'default'
        properties: {
          addressPrefix: '10.200.0.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: '${name}-pip'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    dnsSettings: {
      domainNameLabel: dnsLabel
    }
  }
}

// When an external subnet is provided, use it directly; otherwise use the inline VNet's subnet
var effectiveSubnetId = subnetId != '' ? subnetId : resourceId('Microsoft.Network/virtualNetworks/subnets', '${name}-vnet', 'default')

resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: '${name}-nic'
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: effectiveSubnetId
          }
          publicIPAddress: {
            id: publicIp.id
          }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
  }
}

// Cloud-init script to install Docker, pull image from ACR, and run SPIRE Server
// Uses managed identity to authenticate to ACR (no passwords)
// NOTE: Placeholders use __PLACEHOLDER__ format to avoid Bicep interpolation conflicts
var cloudInitTemplate = '''#cloud-config
package_update: true
packages:
  - docker.io
  - jq
runcmd:
  - systemctl enable docker
  - systemctl start docker
  - sleep 30
  - |
    for i in $(seq 1 10); do
      ACR_TOKEN=$(curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r .access_token)
      if [ -n "$ACR_TOKEN" ] && [ "$ACR_TOKEN" != "null" ]; then
        echo "Got MSI token on attempt $i"
        break
      fi
      echo "Waiting for MSI token (attempt $i)..."
      sleep 10
    done
  - |
    ACR_SERVER="__ACR_SERVER__"
    REFRESH_TOKEN=$(curl -s -X POST "https://$ACR_SERVER/oauth2/exchange" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=access_token&service=$ACR_SERVER&access_token=$ACR_TOKEN" | jq -r .refresh_token)
    ACCESS_TOKEN=$(curl -s -X POST "https://$ACR_SERVER/oauth2/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=refresh_token&service=$ACR_SERVER&scope=repository:spiffe-proxy:pull&refresh_token=$REFRESH_TOKEN" | jq -r .access_token)
    echo "$ACCESS_TOKEN" | docker login "$ACR_SERVER" -u 00000000-0000-0000-0000-000000000000 --password-stdin
  - |
    docker pull __CONTAINER_IMAGE__
    docker run -d \
      --name spire-server \
      --restart always \
      -p 8081:8081 \
      --log-driver=syslog \
      --log-opt tag=spire-server \
      -e CONTAINER_MODE=server \
      -e AZURE_TENANT_ID=__TENANT_ID__ \
      __CONTAINER_IMAGE__
'''

var cloudInitResolved = replace(
  replace(
    replace(cloudInitTemplate, '__ACR_SERVER__', registryServer),
    '__CONTAINER_IMAGE__', containerImage),
  '__TENANT_ID__', azureTenantId)

resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = {
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
    hardwareProfile: {
      vmSize: 'Standard_B2s'
    }
    osProfile: {
      computerName: name
      adminUsername: 'azureuser'
      customData: base64(cloudInitResolved)
      // SSH is used for all VM operations (replacing unreliable `az vm run-command`).
      // When an SSH public key is available, disable password auth.
      // When no key is available (fresh deploy), fall back to password auth with a
      // deployment-scoped password. deploy.sh auto-detects ~/.ssh/id_*.pub.
      adminPassword: 'P${uniqueString(resourceGroup().id, deployment().name)}x1!'
      linuxConfiguration: {
        // Always false — Azure does not allow toggling this on existing VMs
        // (PropertyChangeNotAllowed). Password is always set as fallback;
        // SSH keys are injected alongside when available.
        disablePasswordAuthentication: false
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
        managedDisk: {
          storageAccountType: 'Standard_LRS'
        }
        diskSizeGB: 30
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
  }
}

// =============================================================================
// Centralized logging: Azure Monitor Agent → Log Analytics
// =============================================================================
// Ships SPIRE server Docker logs (via syslog) to the same Log Analytics workspace
// that Container Apps uses. This preserves logs across VM restarts and enables
// diagnosis of SPIRE server hangs without SSH/run-command access.
//
// Query in Log Analytics:
//   Syslog | where ProcessName == "spire-server" | order by TimeGenerated desc
// =============================================================================

resource amaExtension 'Microsoft.Compute/virtualMachines/extensions@2024-03-01' = if (logAnalyticsWorkspaceId != '') {
  parent: vm
  name: 'AzureMonitorLinuxAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorLinuxAgent'
    typeHandlerVersion: '1.33'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
    settings: {
      authentication: {
        managedIdentity: {
          'identifier-name': 'mi_res_id'
          'identifier-value': identity.id
        }
      }
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' = if (logAnalyticsWorkspaceId != '') {
  name: '${name}-dcr'
  location: location
  tags: tags
  properties: {
    dataSources: {
      syslog: [
        {
          name: 'syslogDaemon'
          streams: ['Microsoft-Syslog']
          facilityNames: ['daemon', 'user']
          logLevels: ['Debug', 'Info', 'Notice', 'Warning', 'Error', 'Critical', 'Alert', 'Emergency']
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: logAnalyticsWorkspaceId
          name: 'logAnalytics'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Microsoft-Syslog']
        destinations: ['logAnalytics']
      }
    ]
  }
}

// Role: Monitoring Metrics Publisher on the DCR for the VM's managed identity
var monitoringPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'

resource dcrMonitoringRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (logAnalyticsWorkspaceId != '') {
  name: guid(dcr.id, identity.id, monitoringPublisherRoleId)
  scope: dcr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringPublisherRoleId)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2022-06-01' = if (logAnalyticsWorkspaceId != '') {
  name: '${name}-dcr-assoc'
  scope: vm
  properties: {
    dataCollectionRuleId: dcr.id
  }
}

output fqdn string = publicIp.properties.dnsSettings.fqdn
output ipAddress string = publicIp.properties.ipAddress
output name string = vm.name
output identityPrincipalId string = identity.properties.principalId
