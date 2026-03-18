# Threat Evidence Tests

This directory contains the threat-evidence harness used to validate EDAMAME runtime detections described in the EDAMAME Security blog posts. The tests are data-driven and produce portable artifacts (sessions, exceptions, summaries) that can be reviewed locally and in CI.

## Contents

- `threat_evidence_scenarios.json`: scenario catalog and expected evidence thresholds
- `run_threat_evidence_lima.sh`: local runner (Ubuntu via Lima recommended)
- `run_threat_evidence_stability.sh`: repeated-run stability check

## Prerequisites

- Ubuntu Lima VM with outbound network access (recommended for local runs)
- `jq`, `curl`, `python3`
- `edamame_posture` available on `PATH` (or set `EDAMAME_POSTURE_CMD`)

## Local Usage

Run a single scenario:

```bash
./tests/threat_evidence/run_threat_evidence_lima.sh --scenario contagious_interview_beaconing --mode enforcement
```

Run the full CI scenario set:

```bash
./tests/threat_evidence/run_threat_evidence_lima.sh --scenario all --mode enforcement --ci-only
```

Run the stability check:

```bash
./tests/threat_evidence/run_threat_evidence_stability.sh \
  --iterations 10 \
  --min-pass-rate 95 \
  --max-unknown 0 \
  --mode enforcement \
  --ci-only
```

## What Each Scenario Does

For each scenario, the runner:

1. Starts EDAMAME Posture in disconnected mode with packet capture enabled
2. Generates baseline traffic
3. Creates and applies a custom whitelist (process-aware when required)
4. Executes the scenario payload
5. Collects evidence from `get-sessions` and `get-exceptions`
6. Writes `result_summary.json` and returns success/failure

## Evidence Output

Local runs write:

- `tests/threat_evidence/artifacts/threat_evidence_local/<timestamp>/<scenario>/payload.log`
- `tests/threat_evidence/artifacts/threat_evidence_local/<timestamp>/<scenario>/sessions.log`
- `tests/threat_evidence/artifacts/threat_evidence_local/<timestamp>/<scenario>/exceptions.log`
- `tests/threat_evidence/artifacts/threat_evidence_local/<timestamp>/<scenario>/result_summary.json`
- `tests/threat_evidence/artifacts/threat_evidence_local/<timestamp>/summary.json`

Stability runs write:

- `tests/threat_evidence/artifacts/threat_evidence_stability/<timestamp>/stability_summary.json`

## CI

Workflow: `.github/workflows/test_threat_evidence.yml`

- Runs scenarios as a matrix (one scenario per job)
- `strict`: scenario failure fails the job
- `observe`: scenario failure is reported but does not fail the job (artifacts still upload)
