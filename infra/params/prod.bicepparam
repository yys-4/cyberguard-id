// params/prod.bicepparam — Production parameter values
// Usage: az deployment group create -g rg-cyberguard-id -f infra/main.bicep -p infra/params/prod.bicepparam

using '../main.bicep'

param location = 'southeastasia'
param nameSuffix = 'prod01'          // Change to a stable suffix (not date-based)
param imageTag = 'latest'
param budgetAlertEmail = 'muhammadayyas1003@gmail.com'
param corsAllowedOrigins = 'https://YOUR_STATIC_WEB_APP_URL'
// param driftMonitorToken = ''       // Inject at deploy time via --parameters driftMonitorToken=<value>
