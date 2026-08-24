# cw-log-retention-guard

[![ci](https://github.com/moveeeax/cw-log-retention-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/cw-log-retention-guard/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Audit and enforce a retention baseline on CloudWatch Log Groups **before the storage bill does it for you.**

New log groups are created with `retentionInDays` unset, so they keep logs *forever*. Across
accounts and regions that quietly accumulates gigabytes nobody will ever read — invisible until the
CloudWatch storage line item spikes. `cw-log-retention-guard` lists every group, flags the ones with
no retention or retention above your baseline, and exits non-zero so it doubles as a CI gate. With
`fix` it applies the policy for you.

## How it works

- `audit` pages through `DescribeLogGroups` and classifies each group:
  - **unbounded** — `retentionInDays` is unset (kept forever)
  - **over-threshold** — retention is set but exceeds `--max-days`
  - **ok** — bounded retention within the threshold
- It prints a table (or `--json`) and **exits `1` when any group violates the baseline**, so a CI
  job fails the moment someone ships an un-bounded log group.
- `fix` re-runs the audit and calls `PutRetentionPolicy(--set-days)` on every violating group,
  leaving compliant groups untouched.

`--max-days 0` disables the over-threshold check and flags only unbounded groups.

## Install

```shell
go install github.com/moveeeax/cw-log-retention-guard@latest
```

Or build from source:

```shell
git clone https://github.com/moveeeax/cw-log-retention-guard.git
cd cw-log-retention-guard
go build -o cw-log-retention-guard .
```

## Usage

```shell
# report offenders as a CI gate (exit 1 on violations)
cw-log-retention-guard audit --max-days 30 --region eu-west-1

# machine-readable
cw-log-retention-guard audit --max-days 30 --json

# enforce a 30-day baseline on every offender
cw-log-retention-guard fix --set-days 30 --max-days 30
```

Example audit output:

```text
LOG GROUP                         RETENTION  STORED     STATUS
/aws/lambda/checkout-prod         never      6.4 GiB    unbounded
/aws/lambda/mailer                365d       210.0 MiB  over-threshold
/aws/rds/instance/pg/postgresql   14d        1.2 GiB    ok

4 group(s), 3 violation(s) (2 unbounded, 1 over-threshold)
```

Credentials and region resolve through the standard AWS chain (`AWS_PROFILE`, `AWS_REGION`,
env vars, shared config). `--region` and `--profile` override them.

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--max-days` | `30` | Flag retention above N days; `0` flags only unbounded groups |
| `--set-days` | `30` | Retention (days) applied by `fix` |
| `--region` | env/profile | AWS region |
| `--profile` | env | AWS shared-config profile |
| `--json` | `false` | Emit JSON instead of a table |

### IAM

`audit` needs `logs:DescribeLogGroups`. `fix` additionally needs `logs:PutRetentionPolicy`.

## As a CI gate

```yaml
- run: cw-log-retention-guard audit --max-days 30 --region us-east-1
  # fails the job (exit 1) if any log group is unbounded or over-threshold
```

## Development

```shell
go test ./...
go vet ./...
```

See [`examples/`](examples/) for sample table and JSON output.

## License

MIT — see [LICENSE](LICENSE).
