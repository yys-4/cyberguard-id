// modules/storage.bicep — Azure Blob Storage for model artifacts and audit logs
param location string
param nameSuffix string

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'stcyberguardid${nameSuffix}'
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource dataContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'cyberguard-data'
  properties: {
    publicAccess: 'None'
  }
}

output blobEndpoint string = storage.properties.primaryEndpoints.blob
output storageAccountName string = storage.name
