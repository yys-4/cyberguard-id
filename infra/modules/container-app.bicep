// modules/container-app.bicep — Azure Container App with system-assigned identity
param location string
param nameSuffix string
param acrLoginServer string
param imageTag string
param keyVaultUrl string
param storageAccountUrl string
param logAnalyticsWorkspaceId string
param logAnalyticsWorkspaceKey string
param corsAllowedOrigins string
@secure()
param driftMonitorToken string = ''

var appName = 'ca-cyberguard-id-${nameSuffix}'
var envName = 'cae-cyberguard-id-${nameSuffix}'

resource containerAppEnv 'Microsoft.App/managedEnvironments@2024-02-02-preview' = {
  name: envName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalyticsWorkspaceId
        sharedKey: logAnalyticsWorkspaceKey
      }
    }
  }
}

resource containerApp 'Microsoft.App/containerApps@2024-02-02-preview' = {
  name: appName
  location: location
  identity: {
    type: 'SystemAssigned'  // Managed Identity for Key Vault + ACR access
  }
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8000
        transport: 'auto'
      }
      registries: [
        {
          server: acrLoginServer
          identity: 'system'  // Phase 3.4: Managed Identity pull
        }
      ]
    }
    template: {
      scale: {
        minReplicas: 0   // Scale-to-zero for free tier cost control
        maxReplicas: 3
        rules: [
          {
            name: 'http-scaling'
            http: { metadata: { concurrentRequests: '20' } }
          }
        ]
      }
      containers: [
        {
          name: 'api'
          image: '${acrLoginServer}/cyberguard-api:${imageTag}'
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: [
            { name: 'APP_ENV', value: 'prod' }
            { name: 'AZURE_KEY_VAULT_URL', value: keyVaultUrl }
            { name: 'AZURE_STORAGE_URL', value: storageAccountUrl }
            { name: 'CORS_ALLOWED_ORIGINS', value: corsAllowedOrigins }
            { name: 'ENABLE_CONFIDENCE_CALIBRATION', value: 'true' }
            { name: 'PERSIST_CALIBRATOR', value: 'true' }
            { name: 'CALIBRATION_DATA_PATH', value: '/app/data/processed/processed_cyber_data.csv' }
            { name: 'CALIBRATOR_PATH', value: '/app/models/probability_calibrator.joblib' }
            { name: 'DEFAULT_SENSITIVITY', value: 'balanced' }
            { name: 'THRESHOLD_LOW', value: '0.75' }
            { name: 'THRESHOLD_BALANCED', value: '0.60' }
            { name: 'THRESHOLD_HIGH', value: '0.45' }
            { name: 'THRESHOLD_UNCERTAINTY_MARGIN', value: '0.05' }
            { name: 'AUTO_SENSITIVITY_SMS', value: 'low' }
            { name: 'AUTO_SENSITIVITY_WHATSAPP', value: 'balanced' }
            { name: 'AUTO_SENSITIVITY_EMAIL', value: 'balanced' }
            { name: 'CHANNEL_PRIOR_WEIGHT', value: '1.00' }
            { name: 'CHANNEL_PRIOR_MIN_SAMPLE', value: '200' }
            { name: 'CHANNEL_PRIOR_SMOOTHING', value: '200.0' }
            { name: 'CHANNEL_PRIOR_MAX_ODDS_RATIO', value: '3.0' }
            { name: 'DRIFT_MONITOR_BEARER_TOKEN', value: driftMonitorToken }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: { path: '/health/live', port: 8000 }
              initialDelaySeconds: 15
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: { path: '/health/ready', port: 8000 }
              initialDelaySeconds: 20
              periodSeconds: 30
            }
          ]
        }
      ]
    }
  }
}

output appUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}'
output principalId string = containerApp.identity.principalId
