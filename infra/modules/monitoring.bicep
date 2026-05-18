// modules/monitoring.bicep — Log Analytics + Application Insights
param location string = resourceGroup().location
param logAnalyticsWorkspaceName string
param appInsightsName string
param keyVaultName string

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsWorkspaceName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
  }
}

// Store App Insights connection string in Key Vault
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

resource appInsightsSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: 'cyberguard-appinsights-connstr'
  properties: {
    value: appInsights.properties.ConnectionString
  }
}

output workspaceId string = logAnalytics.properties.customerId
output workspacePrimaryKey string = logAnalytics.listKeys().primarySharedKey
output appInsightsConnectionString string = appInsights.properties.ConnectionString
