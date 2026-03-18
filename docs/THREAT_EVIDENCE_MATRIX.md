# Threat Evidence Matrix

This matrix links blog-described threat chains to executable test scenarios and measurable EDAMAME evidence signals.

Source narrative: [2 real attacks every individual developer should model with a Personal CISO](https://www.edamame.tech/blog-full/2-real-attacks-personal-ciso-individual-developer).

## Scenario Mapping

| Blog Threat Narrative | Scenario ID | Primary Signal Planes | Evidence Produced |
| --- | --- | --- | --- |
| Contagious Interview / DEV#POPPER staged beaconing | `contagious_interview_beaconing` | Traffic monitoring with L7 process association | Whitelist nonconforming sessions and session log evidence |
| Contagious Interview process identity abuse | `contagious_interview_process_masquerade` | Traffic monitoring with L7 process association | Process-aware whitelist mismatch evidence |
| Contagious Interview remote-control style channel | `contagious_interview_remote_control_pattern` | Traffic monitoring with L7 process association | Sustained outbound session evidence in sessions and exceptions |
| Nearest-neighbor style reconnaissance burst | `nearest_neighbor_recon_burst` | LAN + traffic behavior evidence | Burst-like multi-target outbound evidence and nonconforming sessions |
| Nearest-neighbor CVE context approximation | `nearest_neighbor_cve_surface` | LAN/CVE correlation context | Nonconforming evidence from vulnerability-intelligence endpoint activity |
| Identity exposure escalation context | `identity_exposure_context_gate` | Identity exposure context | Nonconforming evidence from breach-intelligence endpoint activity |

## Evidence Format

Each scenario emits:

- `payload.log`: exact payload execution transcript.
- `sessions.log`: `edamame_posture get-sessions` output.
- `exceptions.log`: `edamame_posture get-exceptions` output.
- `result_summary.json`: normalized assertions and observed counters.

Aggregate run summary:

- `summary.json` (single run)
- `stability_summary.json` (repeated-run gate)

## Local Validation

Run the scenario suite locally (Ubuntu via Lima recommended):

```bash
./tests/run_threat_evidence_lima.sh --scenario all --mode enforcement --ci-only
```

To measure run-to-run stability:

```bash
./tests/run_threat_evidence_stability.sh --iterations 10 --min-pass-rate 95 --max-unknown 0 --mode enforcement --ci-only
```

## CI Behavior

Workflow: `.github/workflows/test_threat_evidence.yml`

- Each scenario runs as its own matrix job
- Evidence artifacts upload on every run
- `strict` mode fails the job when the scenario does not produce the expected detection signal
