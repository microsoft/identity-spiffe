param name string
param location string
param tags object

@description('Optional subnet resource ID for VNet integration. When provided, the ACA environment is injected into this subnet. Must be delegated to Microsoft.App/environments with a /23 or larger CIDR.')
param infrastructureSubnetId string = ''

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: '${name}-logs'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: name
  location: location
  tags: tags
  properties: union({
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }, infrastructureSubnetId != '' ? {
    vnetConfiguration: {
      infrastructureSubnetId: infrastructureSubnetId
      internal: false
    }
  } : {})
}

output environmentId string = environment.id
output name string = environment.name
output logAnalyticsWorkspaceId string = logAnalytics.id
