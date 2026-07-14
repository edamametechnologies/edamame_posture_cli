# Using EDAMAME Posture with Managed & Cloud Coding Agents

Managed and cloud coding agents — Cursor background/cloud agents, Claude Code sandboxes,
CI runners, hosted agent VMs — execute code and reach your repositories from environments
you don't fully control. EDAMAME Posture lets you:

1. **Gate access to private repositories** so an agent can only reach them from a
   security-compliant environment, and
2. **Continuously monitor** that environment (posture score, network activity, and — with
   the EDAMAME agent integrations — the agent's own behavior) while it runs.

This guide shows how to wire EDAMAME Posture into the common managed-agent environments.

## How the gate works (at a glance)

EDAMAME gates repository access at the **network layer**, using your source-control
provider's own controls, so it holds even if an agent ignores advisory instructions:

1. Enable your GitHub organization's **IP allow list** (GitHub → Organization → Settings →
   Authentication security). With it on, GitHub denies API, Actions, and `git` access to
   your private repos from any source IP that isn't on the list — a valid token is not
   enough.
2. Run `edamame_posture` in **connected mode** inside the agent's environment. It registers
   the environment with the **EDAMAME Hub** and reports its security posture.
3. If the environment satisfies your Hub policy, the Hub grants access for its egress IP;
   the agent can now reach your private repos. When the environment stops reporting or
   falls out of policy, the Hub withdraws that access again.

You define "compliant" (minimum score, required/forbidden threats, tags) once in the
[EDAMAME Hub](https://hub.edamame.tech); the agent environments just report in.

## Prerequisites

- An EDAMAME Hub account and domain ([hub.edamame.tech](https://hub.edamame.tech)).
- Your GitHub organization's IP allow list enabled.
- A conditional-access policy defined in the Hub.
- Hub credentials available to the agent environment as **secrets** (never hard-coded):
  user (email), domain, and a one-time PIN.

Store these in your platform's secret store, e.g. as `EDAMAME_POSTURE_USER`,
`EDAMAME_POSTURE_DOMAIN`, `EDAMAME_POSTURE_PIN`.

## Wiring recipes

### GitHub Actions runners

Use the [`edamame_posture_action`](https://github.com/edamametechnologies/edamame_posture_action)
with connected-mode inputs. `wait_for_api: true` blocks until GitHub has granted this
runner access, which is required for github-hosted runners (their egress IPs are never
pre-listed):

```yaml
- name: Setup EDAMAME Posture
  uses: edamametechnologies/edamame_posture_action@v1
  with:
    edamame_user:   ${{ vars.EDAMAME_POSTURE_USER }}
    edamame_domain: ${{ vars.EDAMAME_POSTURE_DOMAIN }}
    edamame_pin:    ${{ secrets.EDAMAME_POSTURE_PIN }}
    edamame_id:     ${{ github.run_id }}   # unique device id per run
    checkout:       true                   # clone once access is granted
    wait_for_api:   true                   # wait for the gate to lift
```

### Cursor background / cloud agents

Cursor cloud agents run a setup command before the agent starts. Bootstrap posture in
`.cursor/environment.json` and wait for the connection before proceeding:

```jsonc
// .cursor/environment.json
{
  "install": "curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture/main/install.sh | sh && sudo edamame_posture start --user \"$EDAMAME_POSTURE_USER\" --domain \"$EDAMAME_POSTURE_DOMAIN\" --pin \"$EDAMAME_POSTURE_PIN\" --device-id \"cursor-$HOSTNAME\" && edamame_posture wait-for-connection"
}
```

> **Where the clone comes from.** The *initial* repository checkout in a Cursor cloud agent
> is performed by Cursor's infrastructure through its GitHub App, not from the agent's own
> VM. That path is governed by GitHub's separate *"IP allow list for installed GitHub
> Apps"* setting. The posture gate covers traffic egressing from the **agent runtime
> itself** — in-session `git pull`/`push`, API calls, package installs. Verify the
> provisioning/clone path for your setup as well.

### Claude Code (sandbox / devcontainer)

Bootstrap posture in your devcontainer so the agent's git egress originates from a
compliant environment:

```jsonc
// .devcontainer/devcontainer.json
{
  "postCreateCommand": "curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture/main/install.sh | sh && sudo edamame_posture start --user \"$EDAMAME_POSTURE_USER\" --domain \"$EDAMAME_POSTURE_DOMAIN\" --pin \"$EDAMAME_POSTURE_PIN\" --device-id \"claude-$HOSTNAME\" && edamame_posture wait-for-connection"
}
```

Pass the credentials via `containerEnv` or your devcontainer secret mechanism.

### Self-hosted agent hosts and developer workstations

- **Self-hosted hosts / VMs:** install with configuration so the service auto-starts in
  connected mode:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/edamametechnologies/edamame_posture/main/install.sh | sh -s -- \
    --user "$EDAMAME_POSTURE_USER" --domain "$EDAMAME_POSTURE_DOMAIN" --pin "$EDAMAME_POSTURE_PIN"
  ```
- **Developer workstations:** the EDAMAME Security app reports posture continuously, so a
  compliant developer machine keeps its own access with no manual step — an unmanaged
  machine on the same network stays blocked.

## Verifying it works

- **Connection:** `edamame_posture wait-for-connection` returns success once the
  environment is registered with the Hub.
- **Gate lifted:** the agent can `git clone` / `git pull` your private repo *after* setup
  and cannot before it. In GitHub Actions, the action's "Wait for API access" step reports
  that access was granted.
- **Hub visibility:** the environment appears in your [EDAMAME Hub](https://hub.edamame.tech)
  fleet with its current score.

## Monitoring beyond the gate

Connected mode also scores the environment continuously and can enforce network whitelists
and live vulnerability-finding gates while the agent runs (see the `start` /
`background-start-disconnected` flags in the [README](README.md)).

Behavioral (two-plane) monitoring of the agent's *own* activity is **automatic and needs no
plugin**: EDAMAME's host-side transcript observer reads any discovered agent's session
transcripts directly and correlates that reasoning-plane intent against the live system-plane
telemetry `edamame_posture` already collects. Any supported agent whose transcripts are on the
host (Cursor, Claude Code, Claude Desktop, Codex, Hermes, OpenClaw) is monitored the moment it
is discovered on disk, and a compromised agent cannot pause or silence that observation.

The matching EDAMAME agent integrations below are **optional and additive** — they do not
provide the core monitoring. They extend it only where the host observer cannot reach:
**off-host coverage** (the agent runs on a remote box, container, or account whose transcripts
the host cannot read), an **in-agent action channel** (security skills, commands, and read-only
posture/verdict views surfaced inside the agent itself), and **pre-execution tool-call
enforcement**:

- [EDAMAME for Cursor](https://github.com/edamametechnologies/edamame_cursor)
- [EDAMAME for Claude Code](https://github.com/edamametechnologies/edamame_claude_code)
- [EDAMAME for Claude Desktop](https://github.com/edamametechnologies/edamame_claude_desktop)
- [EDAMAME for OpenClaw](https://github.com/edamametechnologies/edamame_openclaw)
- [EDAMAME for Codex](https://github.com/edamametechnologies/edamame_codex)

## Notes and caveats

- **Per-IP granularity.** The gate is enforced per source IP. Environments sharing one NAT
  egress are granted and revoked together; prefer per-agent / per-runner egress where
  isolation matters.
- **Grant and revoke are asynchronous.** Access is added after posture is reported and the
  change propagates, and removed after the Hub sees the environment stop reporting or fall
  out of policy. Always `wait-for-connection` / `wait_for_api` before the agent touches the
  repo.
- **Provisioning path.** As noted for Cursor, an agent platform's initial checkout may
  traverse a GitHub App path rather than the agent's own egress; confirm both.

## Related

- [`edamame_posture_action`](https://github.com/edamametechnologies/edamame_posture_action)
  — GitHub Action wrapper (`wait_for_api`, `wait_for_https`, connected-mode inputs).
- [EDAMAME Hub](https://hub.edamame.tech) — conditional-access policy and fleet visibility.
- [README](README.md) — full `edamame_posture` command reference.
