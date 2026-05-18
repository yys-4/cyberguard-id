// modules/acr.bicep — Azure Container Registry
param location string
param nameSuffix string

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: 'acrcyberguardid${nameSuffix}'
  location: location
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: false  // Phase 3.4: Managed Identity pull only
    publicNetworkAccess: 'Enabled'
  }
}

output loginServer string = acr.properties.loginServer
output acrName string = acr.name
