package ecr

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// WO-16: mockEC2Client implements EC2API for testing.
type mockEC2Client struct {
	regions []string
	err     error
}

func (m *mockEC2Client) DescribeRegions(_ context.Context, _ *ec2.DescribeRegionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	var out ec2.DescribeRegionsOutput
	for _, r := range m.regions {
		name := r
		out.Regions = append(out.Regions, ec2types.Region{RegionName: &name})
	}
	return &out, nil
}

// WO-16: ListRegions returns enabled regions sorted by name.
func TestListRegions(t *testing.T) {
	mock := &mockEC2Client{regions: []string{"us-east-1", "eu-west-1", "ap-south-1"}}
	got, err := ListRegions(context.Background(), mock)
	if err != nil {
		t.Fatalf("ListRegions error: %v", err)
	}
	want := []string{"ap-south-1", "eu-west-1", "us-east-1"}
	if len(got) != len(want) {
		t.Fatalf("got %d regions, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("region[%d] = %s, want %s", i, got[i], w)
		}
	}
}
