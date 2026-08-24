// Package guard audits CloudWatch Log Groups for a retention baseline and,
// optionally, enforces one by setting a retention policy on the offenders.
package guard

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// CWLogsAPI is the slice of the CloudWatch Logs API this tool depends on.
// The concrete *cloudwatchlogs.Client satisfies it; tests use a mock.
type CWLogsAPI interface {
	DescribeLogGroups(context.Context, *cloudwatchlogs.DescribeLogGroupsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
	PutRetentionPolicy(context.Context, *cloudwatchlogs.PutRetentionPolicyInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutRetentionPolicyOutput, error)
}

// Status classifies a log group against the retention baseline.
type Status string

const (
	// StatusOK means the group has a bounded retention within the threshold.
	StatusOK Status = "ok"
	// StatusUnbounded means retentionInDays is unset — logs are kept forever.
	StatusUnbounded Status = "unbounded"
	// StatusOverThreshold means retention is set but exceeds --max-days.
	StatusOverThreshold Status = "over-threshold"
)

// Finding is the audit result for a single log group.
type Finding struct {
	LogGroup      string `json:"logGroup"`
	RetentionDays *int32 `json:"retentionDays"` // nil = never expire
	StoredBytes   int64  `json:"storedBytes"`
	Status        Status `json:"status"`
	Fixed         bool   `json:"fixed,omitempty"`
	NewRetention  *int32 `json:"newRetentionDays,omitempty"`
}

// Violation reports whether this finding breaches the baseline.
func (f Finding) Violation() bool { return f.Status != StatusOK }

// Report is the full audit over a region.
type Report struct {
	Region   string    `json:"region"`
	MaxDays  int32     `json:"maxDays"`
	Findings []Finding `json:"findings"`
}

// Violations returns only the findings that breach the baseline.
func (r *Report) Violations() []Finding {
	var v []Finding
	for _, f := range r.Findings {
		if f.Violation() {
			v = append(v, f)
		}
	}
	return v
}

// HasViolations reports whether any finding breaches the baseline.
func (r *Report) HasViolations() bool {
	for _, f := range r.Findings {
		if f.Violation() {
			return true
		}
	}
	return false
}

// Counts returns totals: groups, unbounded, over-threshold.
func (r *Report) Counts() (total, unbounded, over int) {
	total = len(r.Findings)
	for _, f := range r.Findings {
		switch f.Status {
		case StatusUnbounded:
			unbounded++
		case StatusOverThreshold:
			over++
		}
	}
	return
}

// listLogGroups pages through DescribeLogGroups until exhausted.
func listLogGroups(ctx context.Context, c CWLogsAPI) ([]types.LogGroup, error) {
	var out []types.LogGroup
	var token *string
	for {
		resp, err := c.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("describe log groups: %w", err)
		}
		out = append(out, resp.LogGroups...)
		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		token = resp.NextToken
	}
	return out, nil
}

// Audit lists every log group and classifies it against maxDays.
// A maxDays of 0 disables the over-threshold check: only unbounded groups
// are flagged.
func Audit(ctx context.Context, c CWLogsAPI, region string, maxDays int32) (*Report, error) {
	groups, err := listLogGroups(ctx, c)
	if err != nil {
		return nil, err
	}
	rep := &Report{Region: region, MaxDays: maxDays}
	for _, g := range groups {
		f := Finding{
			LogGroup:      aws.ToString(g.LogGroupName),
			RetentionDays: g.RetentionInDays,
			StoredBytes:   aws.ToInt64(g.StoredBytes),
		}
		switch {
		case g.RetentionInDays == nil:
			f.Status = StatusUnbounded
		case maxDays > 0 && *g.RetentionInDays > maxDays:
			f.Status = StatusOverThreshold
		default:
			f.Status = StatusOK
		}
		rep.Findings = append(rep.Findings, f)
	}
	sort.Slice(rep.Findings, func(i, j int) bool {
		return rep.Findings[i].LogGroup < rep.Findings[j].LogGroup
	})
	return rep, nil
}

// Fix applies PutRetentionPolicy(setDays) to every violating group in rep,
// mutating the findings in place to record the change. It stops at the first
// API error so a partial run is reported truthfully.
func Fix(ctx context.Context, c CWLogsAPI, rep *Report, setDays int32) (int, error) {
	fixed := 0
	for i := range rep.Findings {
		f := &rep.Findings[i]
		if !f.Violation() {
			continue
		}
		_, err := c.PutRetentionPolicy(ctx, &cloudwatchlogs.PutRetentionPolicyInput{
			LogGroupName:    aws.String(f.LogGroup),
			RetentionInDays: aws.Int32(setDays),
		})
		if err != nil {
			return fixed, fmt.Errorf("set retention on %s: %w", f.LogGroup, err)
		}
		nd := setDays
		f.Fixed = true
		f.NewRetention = &nd
		fixed++
	}
	return fixed, nil
}
