package pricing

import (
	"math"
	"testing"
)

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < 0.0001
}

func TestMonthlyStorageCostECR(t *testing.T) {
	// 1 GB = 1073741824 bytes, at $0.10/GB = $0.10
	cost := MonthlyStorageCost("ecr", "us-east-1", 1073741824)
	if !almostEqual(cost, 0.10) {
		t.Errorf("1GB ECR cost = %f, want 0.10", cost)
	}
}

func TestMonthlyStorageCostECRLargeImage(t *testing.T) {
	// 5 GB
	cost := MonthlyStorageCost("ecr", "eu-west-1", 5*1073741824)
	if !almostEqual(cost, 0.50) {
		t.Errorf("5GB ECR cost = %f, want 0.50", cost)
	}
}

func TestMonthlyStorageCostAR(t *testing.T) {
	cost := MonthlyStorageCost("artifactregistry", "us-central1", 1073741824)
	if !almostEqual(cost, 0.10) {
		t.Errorf("1GB AR cost = %f, want 0.10", cost)
	}
}

func TestMonthlyStorageCostARDefaultRegion(t *testing.T) {
	cost := MonthlyStorageCost("artifactregistry", "unknown-region", 1073741824)
	if !almostEqual(cost, 0.10) {
		t.Errorf("1GB AR unknown region cost = %f, want 0.10", cost)
	}
}

func TestMonthlyStorageCostUnknownProvider(t *testing.T) {
	cost := MonthlyStorageCost("unknown", "us-east-1", 1073741824)
	if !almostEqual(cost, 0.10) {
		t.Errorf("1GB unknown provider cost = %f, want 0.10 (fallback)", cost)
	}
}

func TestMonthlyStorageCostZeroBytes(t *testing.T) {
	cost := MonthlyStorageCost("ecr", "us-east-1", 0)
	if cost != 0 {
		t.Errorf("0 bytes cost = %f, want 0", cost)
	}
}

func TestMonthlyStorageCostSmallImage(t *testing.T) {
	// 100 MB = 104857600 bytes
	cost := MonthlyStorageCost("ecr", "us-east-1", 104857600)
	expected := 0.10 * (100.0 / 1024.0)
	if !almostEqual(cost, expected) {
		t.Errorf("100MB ECR cost = %f, want %f", cost, expected)
	}
}

func TestLookupCostPerGB(t *testing.T) {
	tests := []struct {
		provider string
		region   string
		want     float64
	}{
		{"ecr", "us-east-1", 0.10},
		{"ecr", "default", 0.10},
		{"artifactregistry", "us-central1", 0.10},
		{"artifactregistry", "default", 0.10},
		{"unknown", "unknown", 0.10},
	}
	for _, tt := range tests {
		got := lookupCostPerGB(tt.provider, tt.region)
		if !almostEqual(got, tt.want) {
			t.Errorf("lookupCostPerGB(%q, %q) = %f, want %f", tt.provider, tt.region, got, tt.want)
		}
	}
}
