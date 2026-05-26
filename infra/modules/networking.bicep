// =============================================================================
// Shared VNet for Identity Research for Agent Management Using SPIFFE Infrastructure
// =============================================================================
// Single VNet shared by the SPIRE server VM and ACA environment, replacing the
// standalone VNet previously defined in spire-server-vm.bicep.
//
// Subnets:
//   - spire-server (10.200.0.0/24): SPIRE server VM with NSG
//   - aca (10.200.2.0/23): Azure Container Apps environment (delegated)
//   - GatewaySubnet (10.200.4.0/27): Reserved for VPN Gateway (cross-cloud)
//
// The GatewaySubnet enables a future VPN Gateway for SPIFFE federation with GCP.
// =============================================================================

param name string
param location string
param tags object

var acaSubnetPrefix = '10.200.2.0/23'

resource spireServerNsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: '${name}-spire-nsg'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowSPIREFromACA'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '8081'
          sourceAddressPrefix: acaSubnetPrefix
          destinationAddressPrefix: '*'
        }
      }
      // SSH required by deploy.sh for VM operations. Restrict in production.
      {
        name: 'AllowSSHInbound'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: ['10.200.0.0/16']
    }
    subnets: [
      {
        name: 'spire-server'
        properties: {
          addressPrefix: '10.200.0.0/24'
          networkSecurityGroup: {
            id: spireServerNsg.id
          }
        }
      }
      {
        name: 'aca'
        properties: {
          addressPrefix: acaSubnetPrefix
          delegations: [
            {
              name: 'Microsoft.App.environments'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      // Name must be exactly 'GatewaySubnet' — Azure VPN Gateway requirement
      {
        name: 'GatewaySubnet'
        properties: {
          addressPrefix: '10.200.4.0/27'
        }
      }
    ]
  }
}

output vnetId string = vnet.id
output vnetName string = vnet.name
output spireServerSubnetId string = resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'spire-server')
output acaSubnetId string = resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'aca')
output gatewaySubnetId string = resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'GatewaySubnet')
