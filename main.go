// Command cw-log-retention-guard audits CloudWatch Log Groups for a retention
// baseline and can enforce one. It exits non-zero when violations are found so
// it works as a CI gate.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/moveeeax/cw-log-retention-guard/internal/guard"
)

// version is overwritten at release time via -ldflags.
var version = "dev"

const usage = `cw-log-retention-guard - keep CloudWatch Log Groups from hoarding logs forever

Usage:
  cw-log-retention-guard audit [flags]   Report groups with no/over-long retention (exit 1 on violations)
  cw-log-retention-guard fix   [flags]   Apply a retention policy to violating groups
  cw-log-retention-guard version

Flags:
  --max-days N    flag retention above N days; 0 flags only unbounded groups (default 30)
  --set-days N    retention (days) applied by fix (default 30)
  --region R      AWS region (default: from environment/profile)
  --profile P     AWS shared-config profile
  --json          emit JSON instead of a table

Examples:
  cw-log-retention-guard audit --max-days 30 --json
  cw-log-retention-guard fix --set-days 30 --max-days 30`

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "audit":
		return runAudit(ctx, args[1:], stdout, stderr)
	case "fix":
		return runFix(ctx, args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s\n", args[0], usage)
		return 2
	}
}

type commonFlags struct {
	maxDays int
	setDays int
	region  string
	profile string
	json    bool
}

func bindCommon(fs *flag.FlagSet) *commonFlags {
	c := &commonFlags{}
	fs.IntVar(&c.maxDays, "max-days", 30, "flag retention above N days (0 = only unbounded)")
	fs.IntVar(&c.setDays, "set-days", 30, "retention in days applied by fix")
	fs.StringVar(&c.region, "region", "", "AWS region")
	fs.StringVar(&c.profile, "profile", "", "AWS shared-config profile")
	fs.BoolVar(&c.json, "json", false, "emit JSON instead of a table")
	return c
}

func newClient(ctx context.Context, c *commonFlags) (*cloudwatchlogs.Client, string, error) {
	opts := []func(*config.LoadOptions) error{}
	if c.region != "" {
		opts = append(opts, config.WithRegion(c.region))
	}
	if c.profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(c.profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, "", err
	}
	return cloudwatchlogs.NewFromConfig(cfg), cfg.Region, nil
}

func runAudit(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	client, region, err := newClient(ctx, c)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	rep, err := guard.Audit(ctx, client, region, int32(c.maxDays))
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if err := render(stdout, rep, c.json); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if rep.HasViolations() {
		return 1
	}
	return 0
}

func runFix(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if c.setDays <= 0 {
		fmt.Fprintln(stderr, "error: --set-days must be a positive number of days")
		return 2
	}
	client, region, err := newClient(ctx, c)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	rep, err := guard.Audit(ctx, client, region, int32(c.maxDays))
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	fixed, err := guard.Fix(ctx, client, rep, int32(c.setDays))
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if err := render(stdout, rep, c.json); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	fmt.Fprintf(stdout, "applied retention=%dd to %d group(s)\n", c.setDays, fixed)
	return 0
}

func render(w io.Writer, rep *guard.Report, asJSON bool) error {
	if asJSON {
		return guard.RenderJSON(w, rep)
	}
	return guard.RenderTable(w, rep)
}
