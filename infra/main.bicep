// main.bicep — CyberGuard-ID infrastructure entrypoint
// Phase 3.2: Replaces fragile bash deploy script with idempotent, auditable IaC.
// Deploy with: az deployment group create -g rg-cyberguard-id -f infra/main.bicep -p infra/params/prod.bicepparam

targetScope = 'resourceGroup'

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Short suffix to ensure globally-unique names (e.g. 12345)')
param nameSuffix string

@description('Container image tag to deploy')
param imageTag string = 'latest'

@description('Email address for cost budget alerts')
param budgetAlertEmail string

@description('CORS allowed origin (the Static Web App URL or localhost)')
param corsAllowedOrigins string = 'http://localhost:5173'

@description('Drift monitor bearer token (store in Key Vault post-deploy)')
@secure()
param driftMonitorToken string = ''

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------

module acr 'modules/acr.bicep' = {
  name: 'acr'
  params: {
    location: location
    nameSuffix: nameSuffix
  }
}

module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: {
    location: location
    nameSuffix: nameSuffix
  }
}

module keyvault 'modules/keyvault.bicep' = {
  name: 'keyvault'
  params: {
    location: location
    nameSuffix: nameSuffix
  }
}

module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring'
  params: {
    location: location
    logAnalyticsWorkspaceName: 'log-cyberguard-id'
    appInsightsName: 'appi-cyberguard-id'
    keyVaultName: keyvault.outputs.keyVaultName
  }
}

module containerApp 'modules/container-app.bicep' = {
  name: 'container-app'
  params: {
    location: location
    nameSuffix: nameSuffix
    acrLoginServer: acr.outputs.loginServer
    imageTag: imageTag
    keyVaultUrl: keyvault.outputs.keyVaultUrl
    storageAccountUrl: storage.outputs.blobEndpoint
    logAnalyticsWorkspaceId: monitoring.outputs.workspaceId
    logAnalyticsWorkspaceKey: monitoring.outputs.workspacePrimaryKey
    corsAllowedOrigins: corsAllowedOrigins
    driftMonitorToken: driftMonitorToken
  }
}

module budget 'modules/budget.bicep' = {
  name: 'budget'
  params: {
    budgetAlertEmail: budgetAlertEmail
  }
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

output appUrl string = containerApp.outputs.appUrl
output acrLoginServer string = acr.outputs.loginServer
output keyVaultUrl string = keyvault.outputs.keyVaultUrl
output storageAccountUrl string = storage.outputs.blobEndpoint
