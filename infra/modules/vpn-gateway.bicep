// =============================================================================
// Azure VPN Gateway for Cross-Cloud Connectivity
// =============================================================================
// Deploys a site-to-site IPsec VPN tunnel between Azure and GCP to enable
// private network connectivity for cross-cloud SPIFFE federation.
//
// Resources:
//   - Public IP (Standard SKU, static) for VPN Gateway
//   - VPN Gateway (VpnGw1, route-based) attached to GatewaySubnet
//   - Local Network Gateway representing the GCP VPN endpoint
//   - VPN Connection (IPsec) linking Azure and GCP gateways
//
// VPN Gateway provisioning takes ~30-45 minutes. This module is deployed
// conditionally — only when gcpVpnPublicIp is provided to main.bicep.
// =============================================================================

@description('Base name for VPN gateway resources.')
param name string

@description('Azure region for all resources.')
param location string

@description('Resource tags.')
param tags object

@description('Resource ID of the GatewaySubnet from the shared networking module.')
param gatewaySubnetId string

@description('Public IP address of the GCP VPN gateway.')
param gcpVpnPublicIp string

@description('GCP VPC address range to route through the VPN tunnel.')
param gcpVpcCidr string = '10.128.0.0/20'

@minLength(12)
@secure()
@description('IPsec pre-shared key for the VPN tunnel. Must be at least 12 characters.')
param sharedKey string

// =============================================================================
// Public IP for VPN Gateway
// =============================================================================

resource publicIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: '${name}-pip'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

// =============================================================================
// VPN Gateway
// =============================================================================

resource vpnGateway 'Microsoft.Network/virtualNetworkGateways@2023-11-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    gatewayType: 'Vpn'
    vpnType: 'RouteBased'
    enableBgp: false
    sku: {
      name: 'VpnGw1AZ'
      tier: 'VpnGw1AZ'
    }
    ipConfigurations: [
      {
        name: 'default'
        properties: {
          publicIPAddress: {
            id: publicIp.id
          }
          subnet: {
            id: gatewaySubnetId
          }
        }
      }
    ]
  }
}

// =============================================================================
// Local Network Gateway (represents the GCP side)
// =============================================================================

resource localNetworkGateway 'Microsoft.Network/localNetworkGateways@2023-11-01' = {
  name: '${name}-lgw'
  location: location
  tags: tags
  properties: {
    gatewayIpAddress: gcpVpnPublicIp
    localNetworkAddressSpace: {
      addressPrefixes: [
        gcpVpcCidr
      ]
    }
  }
}

// =============================================================================
// VPN Connection (IPsec tunnel)
// =============================================================================

resource vpnConnection 'Microsoft.Network/connections@2023-11-01' = {
  name: '${name}-connection'
  location: location
  tags: tags
  properties: {
    connectionType: 'IPsec'
    virtualNetworkGateway1: {
      id: vpnGateway.id
      properties: {}
    }
    localNetworkGateway2: {
      id: localNetworkGateway.id
      properties: {}
    }
    sharedKey: sharedKey
    enableBgp: false
    connectionProtocol: 'IKEv2'
    dpdTimeoutSeconds: 20
    ipsecPolicies: [
      {
        saLifeTimeSeconds: 27000
        saDataSizeKilobytes: 102400000
        ipsecEncryption: 'AES256'
        ipsecIntegrity: 'SHA256'
        ikeEncryption: 'AES256'
        ikeIntegrity: 'SHA256'
        dhGroup: 'DHGroup14'
        pfsGroup: 'PFS2048'
      }
    ]
  }
}

// =============================================================================
// Outputs
// =============================================================================

@description('Public IP address assigned to the VPN Gateway.')
output gatewayPublicIp string = publicIp.properties.ipAddress

@description('Resource ID of the VPN Gateway.')
output gatewayId string = vpnGateway.id
