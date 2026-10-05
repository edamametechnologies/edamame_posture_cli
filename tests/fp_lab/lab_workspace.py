#!/usr/bin/env python3
"""Workspace fixtures for the FP lab.

Every fixture is built under the lab root (default ``~/fp-lab/ws``), never in
OS temp: temp is reserved for the scenarios whose point is temp behaviour,
and those create their own ``mktemp -d`` directory at run time.

The base directory comes from the shared harness
(``agent_harness.make_scratch_workspace``, the same helper the fleet E2E uses)
with ``root`` pointed at the lab root; the fixture then lays a small,
realistic repository on top of it.

Nothing here is a credential. ``secret_shaped_fixtures`` uses AWS's published
documentation example key pair and an obviously fake PEM body, which is the
shape (secret-looking test fixtures) behind the 2.0.6 ``claude`` file-history
finding.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Callable, Dict

from agent_harness import make_scratch_workspace

LAB_GIT_ENV = {
    "GIT_AUTHOR_NAME": "FP Lab",
    "GIT_AUTHOR_EMAIL": "fp-lab@example.invalid",
    "GIT_COMMITTER_NAME": "FP Lab",
    "GIT_COMMITTER_EMAIL": "fp-lab@example.invalid",
}


def _write(base: Path, rel: str, text: str) -> None:
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _git_init(base: Path) -> None:
    """Initialise a git repository with one commit, never touching the user's
    global git configuration (identity comes from the environment)."""
    env = dict(os.environ)
    env.update(LAB_GIT_ENV)
    for cmd in (
        ["git", "init", "-q", "-b", "main"],
        ["git", "add", "-A"],
        ["git", "commit", "-q", "-m", "Initial import"],
    ):
        subprocess.run(cmd, cwd=str(base), env=env, check=True,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")


def _webapp_files(base: Path) -> None:
    _write(base, "README.md", (
        "# inventory-service\n\n"
        "A small inventory API used by the warehouse dashboard.\n\n"
        "Detection rules are mirrored from "
        "https://github.com/edamametechnologies/threatmodels and refreshed weekly.\n\n"
        "## Development\n\n"
        "```\npython3 -m unittest discover -s tests\n```\n"
    ))
    _write(base, "config/services.toml", (
        "[error_reporting]\n"
        "provider = \"sentry\"\n"
        "dsn_host = \"o0.ingest.sentry.io\"\n"
        "status_page = \"https://status.sentry.io\"\n\n"
        "[packages]\n"
        "index_url = \"https://pypi.org/simple\"\n\n"
        "[rules]\n"
        "mirror = \"https://raw.githubusercontent.com/edamametechnologies/threatmodels/main\"\n"
    ))
    _write(base, ".github/workflows/ci.yml", (
        "name: ci\n"
        "on: [push]\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: python3 -m unittest discover -s tests\n"
        "      - run: curl -fsS https://api.github.com/zen\n"
    ))
    _write(base, "package.json", (
        "{\n"
        "  \"name\": \"inventory-dashboard\",\n"
        "  \"version\": \"0.1.0\",\n"
        "  \"private\": true,\n"
        "  \"repository\": \"https://github.com/example-org/inventory-service\",\n"
        "  \"scripts\": {\"test\": \"node --test\"}\n"
        "}\n"
    ))
    _write(base, "pyproject.toml", (
        "[project]\n"
        "name = \"inventory-service\"\n"
        "version = \"0.1.0\"\n"
        "dependencies = [\"requests>=2.31\"]\n\n"
        "[project.urls]\n"
        "Homepage = \"https://github.com/example-org/inventory-service\"\n"
    ))
    _write(base, "src/inventory/__init__.py", "")
    _write(base, "src/inventory/app.py", (
        "def count_items(items):\n"
        "    \"\"\"Return the number of items with a positive quantity.\"\"\"\n"
        "    return sum(1 for item in items if item.get('qty', 0) > 0)\n"
    ))
    _write(base, "tests/__init__.py", "")
    _write(base, "tests/test_app.py", (
        "import sys\nimport unittest\nfrom pathlib import Path\n\n"
        "sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))\n\n"
        "from inventory.app import count_items  # noqa: E402\n\n\n"
        "class CountItemsTest(unittest.TestCase):\n"
        "    def test_counts_positive_quantities(self):\n"
        "        self.assertEqual(count_items([{'qty': 1}, {'qty': 0}, {'qty': 3}]), 2)\n\n\n"
        "if __name__ == '__main__':\n    unittest.main()\n"
    ))
    _write(base, "notes/.keep", "")


def _instruction_files(base: Path) -> None:
    _write(base, "AGENTS.md", (
        "# Agent guide\n\n"
        "- Run `python3 -m unittest discover -s tests` before proposing a change.\n"
        "- Keep functions small and typed where practical.\n"
        "- Never commit credentials; configuration secrets come from the environment.\n"
    ))
    _write(base, "CLAUDE.md", "See AGENTS.md. Prefer small, reviewable diffs.\n")
    _write(base, ".claude/CLAUDE.md", (
        "# Project memory\n\n"
        "- The service is read-only towards the warehouse database.\n"
        "- Tests live in tests/ and use unittest.\n"
    ))
    _write(base, ".cursor/rules/style.mdc", (
        "---\ndescription: Code style\nalwaysApply: true\n---\n\n"
        "- Use four-space indentation.\n- Name tests test_<behaviour>.\n"
    ))
    _write(base, ".cursor/rules/safety/no-secrets.mdc", (
        "---\ndescription: Secrets handling\nalwaysApply: true\n---\n\n"
        "- Do not print environment variables.\n"
        "- Do not read files under ~/.ssh or ~/.aws.\n"
    ))
    _write(base, ".github/copilot-instructions.md", (
        "Suggest unittest-based tests and keep the public API of src/inventory stable.\n"
    ))


def _secret_shaped_files(base: Path) -> None:
    # AWS's documentation example credentials and a fake PEM body: secret-SHAPED,
    # not secret. This is what test fixtures in real repositories look like.
    _write(base, "tests/fixtures/__init__.py", "")
    _write(base, "tests/fixtures/sample_settings.py", (
        "\"\"\"Fixture settings used by the settings loader tests (not real credentials).\"\"\"\n\n"
        "DEFAULT_REGION = \"eu-west-1\"\n"
        "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n"
        "AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n"
        "DEPLOY_KEY = \"\"\"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "ZmFrZS1rZXktbWF0ZXJpYWwtZm9yLXRlc3RzLW9ubHktbm90LWEtcmVhbC1rZXk=\n"
        "-----END OPENSSH PRIVATE KEY-----\"\"\"\n"
    ))
    _write(base, "tests/test_settings.py", (
        "import unittest\n\n"
        "from tests.fixtures import sample_settings\n\n\n"
        "class SettingsTest(unittest.TestCase):\n"
        "    def test_region_is_set(self):\n"
        "        self.assertTrue(sample_settings.DEFAULT_REGION)\n\n\n"
        "if __name__ == '__main__':\n    unittest.main()\n"
    ))


def build_empty(base: Path) -> None:
    _write(base, "README.md", "# FP lab direct scenario workspace\n")


def build_webapp_repo(base: Path) -> None:
    _webapp_files(base)
    _git_init(base)


def build_instruction_repo(base: Path) -> None:
    _webapp_files(base)
    _instruction_files(base)
    _git_init(base)


def build_secret_shaped_fixtures(base: Path) -> None:
    _webapp_files(base)
    _secret_shaped_files(base)
    _git_init(base)


FIXTURES: Dict[str, Callable[[Path], None]] = {
    "empty": build_empty,
    "webapp_repo": build_webapp_repo,
    "instruction_repo": build_instruction_repo,
    "secret_shaped_fixtures": build_secret_shaped_fixtures,
}


def make_workspace(fixture: str, agent_type: str, root: Path) -> Path:
    """Create a fresh workspace for one case under ``root`` and lay the
    fixture on it. The scratch files the shared helper writes (README.md,
    hello.py) are part of the base; fixtures overwrite README.md."""
    base = make_scratch_workspace(agent_type or "direct", root=root)
    FIXTURES[fixture](base)
    return base
