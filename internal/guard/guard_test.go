package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// mockCWLogs implements CWLogsAPI. DescribeLogGroups walks `pages`, using the
// NextToken as a 1-based cursor into the slice so pagination is exercised.
type mockCWLogs struct {
	pages       [][]types.LogGroup
	describeErr error
	putErr      error
	putCalls    []cloudwatchlogs.PutRetentionPolicyInput
}

func (m *mockCWLogs) DescribeLogGroups(_ context.Context, in *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	if m.describeErr != nil {
		return nil, m.describeErr
	}
	idx := 0
	if in.NextToken != nil {
		// tokens are "1", "2", ... pointing at the next page.
		switch *in.NextToken {
		case "1":
			idx = 1
		case "2":
			idx = 2
		}
	}
	out := &cloudwatchlogs.DescribeLogGroupsOutput{LogGroups: m.pages[idx]}
	if idx+1 < len(m.pages) {
		next := "1"
		if idx+1 == 2 {
			next = "2"
		}
		out.NextToken = aws.String(next)
	}
	return out, nil
}

func (m *mockCWLogs) PutRetentionPolicy(_ context.Context, in *cloudwatchlogs.PutRetentionPolicyInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutRetentionPolicyOutput, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}
	m.putCalls = append(m.putCalls, *in)
	return &cloudwatchlogs.PutRetentionPolicyOutput{}, nil
}

func lg(name string, retention *int32, stored int64) types.LogGroup {
	return types.LogGroup{LogGroupName: aws.String(name), RetentionInDays: retention, StoredBytes: aws.Int64(stored)}
}

func TestAuditClassifies(t *testing.T) {
	m := &mockCWLogs{pages: [][]types.LogGroup{{
		lg("/aws/lambda/keeps-forever", nil, 5<<30),
		lg("/aws/lambda/too-long", aws.Int32(90), 1<<20),
		lg("/aws/lambda/within", aws.Int32(14), 1<<20),
	}}}

	rep, err := Audit(context.Background(), m, "eu-west-1", 30)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(rep.Findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(rep.Findings))
	}
	byName := map[string]Status{}
	for _, f := range rep.Findings {
		byName[f.LogGroup] = f.Status
	}
	if got := byName["/aws/lambda/keeps-forever"]; got != StatusUnbounded {
		t.Errorf("keeps-forever: want unbounded, got %s", got)
	}
	if got := byName["/aws/lambda/too-long"]; got != StatusOverThreshold {
		t.Errorf("too-long: want over-threshold, got %s", got)
	}
	if got := byName["/aws/lambda/within"]; got != StatusOK {
		t.Errorf("within: want ok, got %s", got)
	}
	if !rep.HasViolations() {
		t.Error("expected violations")
	}
	if n := len(rep.Violations()); n != 2 {
		t.Errorf("want 2 violations, got %d", n)
	}
}

func TestAuditSortedAndFindingsPaginated(t *testing.T) {
	m := &mockCWLogs{pages: [][]types.LogGroup{
		{lg("zeta", aws.Int32(7), 0)},
		{lg("alpha", nil, 0)},
		{lg("mike", aws.Int32(1), 0)},
	}}
	rep, err := Audit(context.Background(), m, "us-east-1", 30)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(rep.Findings) != 3 {
		t.Fatalf("pagination lost groups: got %d", len(rep.Findings))
	}
	want := []string{"alpha", "mike", "zeta"}
	for i, f := range rep.Findings {
		if f.LogGroup != want[i] {
			t.Errorf("finding %d: want %s, got %s", i, want[i], f.LogGroup)
		}
	}
}

func TestAuditMaxDaysZeroOnlyFlagsUnbounded(t *testing.T) {
	m := &mockCWLogs{pages: [][]types.LogGroup{{
		lg("bounded-long", aws.Int32(3650), 0),
		lg("unbounded", nil, 0),
	}}}
	rep, err := Audit(context.Background(), m, "us-east-1", 0)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if n := len(rep.Violations()); n != 1 {
		t.Fatalf("want 1 violation with maxDays=0, got %d", n)
	}
	if rep.Violations()[0].LogGroup != "unbounded" {
		t.Errorf("wrong group flagged: %s", rep.Violations()[0].LogGroup)
	}
}

func TestAuditPropagatesError(t *testing.T) {
	m := &mockCWLogs{describeErr: errors.New("throttled")}
	if _, err := Audit(context.Background(), m, "us-east-1", 30); err == nil {
		t.Fatal("expected error from describe")
	}
}

func TestFixSetsRetentionOnViolationsOnly(t *testing.T) {
	m := &mockCWLogs{pages: [][]types.LogGroup{{
		lg("unbounded", nil, 0),
		lg("ok", aws.Int32(30), 0),
		lg("too-long", aws.Int32(365), 0),
	}}}
	rep, err := Audit(context.Background(), m, "us-east-1", 30)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	fixed, err := Fix(context.Background(), m, rep, 30)
	if err != nil {
		t.Fatalf("fix: %v", err)
	}
	if fixed != 2 {
		t.Fatalf("want 2 fixed, got %d", fixed)
	}
	if len(m.putCalls) != 2 {
		t.Fatalf("want 2 PutRetentionPolicy calls, got %d", len(m.putCalls))
	}
	for _, c := range m.putCalls {
		if aws.ToInt32(c.RetentionInDays) != 30 {
			t.Errorf("wrong retention set: %d", aws.ToInt32(c.RetentionInDays))
		}
		if aws.ToString(c.LogGroupName) == "ok" {
			t.Error("fix touched a compliant group")
		}
	}
}

func TestFixReportsError(t *testing.T) {
	m := &mockCWLogs{
		pages:  [][]types.LogGroup{{lg("unbounded", nil, 0)}},
		putErr: errors.New("access denied"),
	}
	rep, err := Audit(context.Background(), m, "us-east-1", 30)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if _, err := Fix(context.Background(), m, rep, 30); err == nil {
		t.Fatal("expected error from put")
	}
}

func TestRenderJSONIncludesFields(t *testing.T) {
	m := &mockCWLogs{pages: [][]types.LogGroup{{lg("g", nil, 2048)}}}
	rep, _ := Audit(context.Background(), m, "us-east-1", 30)
	var buf bytes.Buffer
	if err := RenderJSON(&buf, rep); err != nil {
		t.Fatalf("render json: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`"region": "us-east-1"`, `"status": "unbounded"`, `"logGroup": "g"`} {
		if !strings.Contains(out, want) {
			t.Errorf("json missing %q\n%s", want, out)
		}
	}
}

func TestRenderTableSummary(t *testing.T) {
	m := &mockCWLogs{pages: [][]types.LogGroup{{
		lg("a", nil, 1<<30),
		lg("b", aws.Int32(365), 0),
		lg("c", aws.Int32(7), 0),
	}}}
	rep, _ := Audit(context.Background(), m, "us-east-1", 30)
	var buf bytes.Buffer
	if err := RenderTable(&buf, rep); err != nil {
		t.Fatalf("render table: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "3 group(s), 2 violation(s) (1 unbounded, 1 over-threshold)") {
		t.Errorf("summary line wrong:\n%s", out)
	}
	if !strings.Contains(out, "never") || !strings.Contains(out, "1.0 GiB") {
		t.Errorf("table body wrong:\n%s", out)
	}
}

func TestValidateRetention(t *testing.T) {
	for _, d := range []int{1, 30, 365, 3653} {
		if err := ValidateRetention(d); err != nil {
			t.Errorf("%d: unexpected error %v", d, err)
		}
	}
	for _, d := range []int{-1, 0, 2, 31, 3650, 1 << 40} {
		if err := ValidateRetention(d); err == nil {
			t.Errorf("%d: expected error", d)
		}
	}
}

func TestFixRejectsInvalidRetentionBeforeAPICall(t *testing.T) {
	m := &mockCWLogs{pages: [][]types.LogGroup{{lg("unbounded", nil, 0)}}}
	rep, err := Audit(context.Background(), m, "us-east-1", 30)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	fixed, err := Fix(context.Background(), m, rep, 45)
	if err == nil {
		t.Fatal("expected error for 45 days")
	}
	if fixed != 0 || len(m.putCalls) != 0 {
		t.Errorf("want no API calls, got fixed=%d calls=%d", fixed, len(m.putCalls))
	}
	if rep.Findings[0].Fixed {
		t.Error("finding marked fixed")
	}
}

func TestPlanListsViolationsOnly(t *testing.T) {
	m := &mockCWLogs{pages: [][]types.LogGroup{{
		lg("unbounded", nil, 0),
		lg("ok", aws.Int32(30), 0),
		lg("too-long", aws.Int32(365), 0),
	}}}
	rep, err := Audit(context.Background(), m, "us-east-1", 30)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	plan := Plan(rep, 14)
	if len(plan) != 2 {
		t.Fatalf("want 2 changes, got %d", len(plan))
	}
	if plan[0].LogGroup != "too-long" || aws.ToInt32(plan[0].From) != 365 || plan[0].To != 14 {
		t.Errorf("change 0 wrong: %+v", plan[0])
	}
	if plan[1].LogGroup != "unbounded" || plan[1].From != nil || plan[1].To != 14 {
		t.Errorf("change 1 wrong: %+v", plan[1])
	}
	if len(m.putCalls) != 0 {
		t.Errorf("plan made %d API calls", len(m.putCalls))
	}
	if rep.Findings[0].Fixed || rep.Findings[2].Fixed {
		t.Error("plan mutated the report")
	}
}

func TestRenderPlanTable(t *testing.T) {
	plan := []Change{
		{LogGroup: "/aws/lambda/mailer", From: aws.Int32(365), To: 30},
		{LogGroup: "/ecs/payments", From: nil, To: 30},
	}
	var buf bytes.Buffer
	if err := RenderPlanTable(&buf, plan); err != nil {
		t.Fatalf("render plan table: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"LOG GROUP", "CURRENT -> NEW", "365d -> 30d", "never -> 30d", "dry run: 2 group(s) would change"} {
		if !strings.Contains(out, want) {
			t.Errorf("plan table missing %q\n%s", want, out)
		}
	}
}

func TestRenderPlanJSON(t *testing.T) {
	var buf bytes.Buffer
	plan := []Change{{LogGroup: "g", From: nil, To: 7}, {LogGroup: "h", From: aws.Int32(90), To: 7}}
	if err := RenderPlanJSON(&buf, plan); err != nil {
		t.Fatalf("render plan json: %v", err)
	}
	var got []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, buf.String())
	}
	if len(got) != 2 || got[0]["group"] != "g" || got[0]["from"] != nil || got[0]["to"] != float64(7) || got[1]["from"] != float64(90) {
		t.Errorf("unexpected plan json: %s", buf.String())
	}

	buf.Reset()
	if err := RenderPlanJSON(&buf, Plan(&Report{}, 7)); err != nil {
		t.Fatalf("render empty plan: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("empty plan should be [], got %q", buf.String())
	}
}
