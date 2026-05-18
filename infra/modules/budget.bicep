// modules/budget.bicep — Azure Cost Management budget alert
// Phase 1.12 + 3.2: $10/month budget with 80% alert email to team
param budgetAlertEmail string
param budgetAmount int = 10

resource budget 'Microsoft.Consumption/budgets@2024-08-01' = {
  name: 'budget-cyberguard-id'
  properties: {
    category: 'Cost'
    amount: budgetAmount
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: '2026-01-01'
    }
    notifications: {
      actualGreaterThan80Percent: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 80
        thresholdType: 'Actual'
        contactEmails: [budgetAlertEmail]
      }
    }
  }
}
