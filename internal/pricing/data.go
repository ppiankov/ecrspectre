package pricing

// StorageCosts maps provider and region to per-GB monthly storage cost in USD.
// ECR: $0.10/GB/month in all regions.
// GCP Artifact Registry: $0.10/GB/month (us/europe/asia single-region),
// varies by multi-region location.
var StorageCosts = map[string]map[string]float64{
	"ecr": {
		"default": 0.10, // ECR is $0.10/GB/month in all regions
	},
	"artifactregistry": {
		"us":              0.10,
		"europe":          0.10,
		"asia":            0.10,
		"us-central1":     0.10,
		"us-east1":        0.10,
		"us-east4":        0.10,
		"us-west1":        0.10,
		"us-west2":        0.10,
		"europe-west1":    0.10,
		"europe-west2":    0.10,
		"europe-west4":    0.10,
		"asia-east1":      0.10,
		"asia-southeast1": 0.10,
		"default":         0.10,
	},
}
