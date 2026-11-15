package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestFixRejectsUnsupportedSetDays(t *testing.T) {
	for _, days := range []string{"0", "-5", "45", "3650"} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), []string{"fix", "--dry-run", "--set-days", days, "--region", "us-east-1"}, &stdout, &stderr)
		if code != 2 {
			t.Errorf("--set-days %s: want exit 2, got %d", days, code)
		}
		if !strings.Contains(stderr.String(), "not accepted by CloudWatch Logs") {
			t.Errorf("--set-days %s: unexpected stderr %q", days, stderr.String())
		}
	}
}
