package pricing

// MonthlyStorageCost calculates the monthly storage cost in USD for a given
// provider, region, and size in bytes.
func MonthlyStorageCost(provider, region string, sizeBytes int64) float64 {
	costPerGB := lookupCostPerGB(provider, region)
	sizeGB := float64(sizeBytes) / (1024 * 1024 * 1024)
	return sizeGB * costPerGB
}

// lookupCostPerGB returns the per-GB monthly cost for a provider/region combination.
func lookupCostPerGB(provider, region string) float64 {
	providerCosts, ok := StorageCosts[provider]
	if !ok {
		return StorageCosts["ecr"]["default"]
	}

	cost, ok := providerCosts[region]
	if !ok {
		return providerCosts["default"]
	}
	return cost
}
