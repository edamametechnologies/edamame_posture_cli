# Pending triggers

Triggers whose detector check ships switched off. They are kept here, out of
the gate runners and out of `catalog.json` (the catalog lists what the
Attack Simulator shows, and a scenario that finds nothing would mislead), and
they move to `triggers/` with the release that switches their check on.

## `trigger_transcript_tamper.py`

A stand-in harness (a copy of the interpreter named `claude`) creates a
transcript under `~/.claude/projects/demo_claude_code_transcript_tamper/` and
its tool child appends to it: `agent_transcript_tampering`, class
`subtree_write`. It runs on macOS and Linux, where a store file's creation is
recorded.

To wire it, with the release that publishes `transcript_write_trust_enabled`
true:

- Move the trigger to `triggers/` and drop its `sys.path` line.
- `run_cve_detection.sh`: add `transcript_tamper` to `SCENARIOS_CSV`, map it
  to `agent_transcript_tampering` in `expected_check_for`, and exclude it on
  Windows (`PLATFORM_EXCLUDED_SCENARIOS` in `check_gate.py`).
- `check_gate.py`: while the agent's store is in `shadow`, the finding is LOW
  with basis `would_grade:high`: the gate asserts the finding and its basis,
  not an alertable band.
- `cleanup.py`: remove `~/.claude/projects/demo_<agent>_transcript_tamper`
  and `~/.demo_<agent>_transcript_tamper_bin`.
- `catalog.json`: an entry in the `ai_agents` theme, for example:

```json
"transcript_tamper": {
  "trigger": "trigger_transcript_tamper.py",
  "title": "Rewrite an AI agent's conversation from one of its tools",
  "one_liner": "A process started by an AI coding agent's tool appends a line to the agent's own conversation transcript, the record the agent and its monitors read back.",
  "reference": {
    "name": "MITRE ATT&CK T1565.001 - Stored Data Manipulation",
    "url": "https://attack.mitre.org/techniques/T1565/001/",
    "kind": "technique"
  },
  "see_in_edamame": "Security > Detections shows an Agent transcript tampering finding naming the writer and the transcript.",
  "appears_within": "usually within a minute or two",
  "talk_track": "An agent's transcript is what it reads back to decide what it was asked to do. EDAMAME records which process creates and writes each transcript, and flags a write by a process the agent started through one of its tools at its next detection tick.",
  "terms": [],
  "needs_admin": false,
  "platforms": ["macos", "linux"],
  "expected_checks": ["agent_transcript_tampering"],
  "gate_scenarios": ["transcript_tamper"]
}
```
