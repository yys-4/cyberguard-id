// modules/keyvault.bicep — Azure Key Vault for runtime secrets
param location string
param nameSuffix string

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-cyberguard-${nameSuffix}'
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true   // RBAC model; no legacy access policies
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'  // Container Apps requires public access
  }
}

output keyVaultUrl string = keyVault.properties.vaultUri
output keyVaultName string = keyVault.name
