#!/usr/bin/env python3
"""
Trigger agent_transcript_tampering: a process below an AI agent's harness
writes the harness's own transcript.

Pending: the write provenance of the transcript stores ships switched off
(`transcript_write_trust_enabled: false` in cve-detection-params-db.json),
so this trigger is kept out of the gate, the catalog and the triggers
directory until the release that switches it on (README.md beside it says
how to wire it).

Shape (class `subtree_write`):

  1. A stand-in harness: a copy of this interpreter named like the agent
     (`claude`), started by the trigger, so the kernel records its start
     and its image names the agent. It creates a transcript under the
     agent's store (`~/.claude/projects/<project>/`): the write provenance
     records it as the transcript's owner.
  2. Its tool child: a plain interpreter the stand-in starts. It appends a
     line to the stand-in's transcript. The writer runs below the store's
     agent and is not the owner: `subtree_write`, HIGH in `alert`, LOW with
     `would_grade:high` in `shadow`.

Everything lives under a project directory with the trigger's prefix, removed
by cleanup.py. The transcript holds synthetic lines only.

Runs on macOS and Linux.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

# The shared helpers live in the triggers directory while this trigger is
# pending.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "triggers"))
from _common import AGENT_TYPE_ARG_HELP, file_prefix_for, resolve_agent_type  # noqa: E402

STORES = {
    # agent type: (store root under the home, the image name of its harness)
    "claude_code": (Path(".claude") / "projects", "claude"),
}


def stand_in_harness(work: Path, image_name: str) -> Path:
    """A copy of this interpreter under the agent's image name."""
    work.mkdir(parents=True, exist_ok=True)
    target = work / image_name
    shutil.copy2(sys.executable, target)
    target.chmod(0o755)
    return target


HARNESS_SCRIPT = r"""
import json, subprocess, sys, time
transcript = sys.argv[1]
tool = sys.argv[2]
with open(transcript, "a", encoding="utf-8") as f:
    f.write(json.dumps({"type": "user", "message": {"role": "user", "content": "list the files"}}) + "\n")
time.sleep(2)
# The tool child: a plain interpreter below the stand-in harness.
subprocess.run([tool, "-c", (
    "import json,sys;"
    "f=open(sys.argv[1],'a',encoding='utf-8');"
    "f.write(json.dumps({'type':'assistant','message':{'role':'assistant','content':'written by a tool'}})+'\\n');"
    "f.close()"
), transcript], check=True)
time.sleep(2)
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--agent-type", default=None, help=AGENT_TYPE_ARG_HELP)
    parser.add_argument("--work-dir", default=None)
    args = parser.parse_args()
    agent_type = resolve_agent_type(args.agent_type)
    if agent_type not in STORES:
        print(f"transcript_tamper: no store for agent type {agent_type}", file=sys.stderr)
        return 2
    if sys.platform.startswith("win"):
        print("transcript_tamper: runs on macOS and Linux")
        return 0
    store_root, image_name = STORES[agent_type]
    prefix = file_prefix_for(agent_type)
    project = Path.home() / store_root / f"{prefix}_transcript_tamper"
    project.mkdir(parents=True, exist_ok=True)
    transcript = project / f"{uuid.uuid4()}.jsonl"
    work = Path(args.work_dir) if args.work_dir else Path.home() / f".{prefix}_transcript_tamper_bin"
    harness = stand_in_harness(work, image_name)
    started = time.time()
    subprocess.run(
        [str(harness), "-c", HARNESS_SCRIPT, str(transcript), sys.executable],
        check=True,
    )
    print(json.dumps({
        "scenario": "transcript_tamper",
        "agent_type": agent_type,
        "transcript": str(transcript),
        "stand_in_harness": str(harness),
        "started_at": started,
        "expected_check": "agent_transcript_tampering",
        "expected_basis": ["store_write:subtree_write", "would_grade:high"],
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
