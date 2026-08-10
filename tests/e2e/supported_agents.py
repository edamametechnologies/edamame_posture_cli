#!/usr/bin/env python3
import argparse
import json
import os
import platform
import sys
from pathlib import Path
from typing import Dict, List, Set


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def registry_path() -> Path:
    """Locate supported_agents/index.json.

    Resolution order mirrors edamame_foundation::supported_agents so the harness
    and the daemon agree on which registry they read:

      1. EDAMAME_SUPPORTED_AGENTS_INDEX (explicit file, what CI exports)
      2. EDAMAME_SUPPORTED_AGENTS_DIR/index.json
      3. a sibling-clone walk from this file upwards
    """
    explicit = os.environ.get("EDAMAME_SUPPORTED_AGENTS_INDEX")
    if explicit:
        return Path(explicit).expanduser()

    directory = os.environ.get("EDAMAME_SUPPORTED_AGENTS_DIR")
    if directory:
        return Path(directory).expanduser() / "index.json"

    here = Path(__file__).resolve()
    for ancestor in here.parents:
        for candidate in (
            ancestor / "supported_agents" / "index.json",
            # edamame_foundation owns the canonical registry. The last probe is
            # the deprecating mirror, kept for the window in which released
            # daemons still resolve from there.
            ancestor / "edamame_foundation" / "supported_agents" / "index.json",
            ancestor / "agent_security" / "supported_agents" / "index.json",
        ):
            if candidate.is_file():
                return candidate

    # Nothing found: return the canonical sibling path so the caller's read
    # error names the location it should have been at.
    return repo_root().parent / "edamame_foundation" / "supported_agents" / "index.json"


def registry_dir() -> Path:
    return registry_path().parent


def load_registry() -> Dict:
    return json.loads(registry_path().read_text(encoding="utf-8"))


def resolve_repo_path(agent: Dict) -> Path:
    env_var = ((agent.get("e2e") or {}).get("repo_env_var")) or ""
    if env_var and os.environ.get(env_var):
        return Path(os.environ[env_var]).expanduser()
    return repo_root().parent / agent["repo_name"]


def _is_windows() -> bool:
    # Python under Git Bash / MSYS still reports `Windows` from platform.system().
    # Check MSYSTEM as well in case a future runtime reports otherwise.
    msystem = os.environ.get("MSYSTEM") or ""
    return (
        platform.system() == "Windows"
        or msystem.startswith(("MINGW", "MSYS", "CYGWIN"))
    )


def _is_darwin() -> bool:
    return platform.system() == "Darwin"


# MCP snippet filename per agent. Mirrors each plugin's setup/install.sh
# (<slug>-mcp.json written into CONFIG_HOME).
_MCP_SNIPPET_NAME = {
    "cursor": "cursor-mcp.json",
    "claude_code": "claude-code-mcp.json",
    "claude_desktop": "claude-desktop-mcp.json",
    "hermes": "hermes-mcp.json",
}


def resolve_install_paths(agent: Dict) -> Dict[str, str]:
    """Resolve platform-aware install paths for an agent.

    Mirrors the rules in each plugin's setup/install.sh:
      - data_dir + Darwin: $HOME/Library/Application Support/<slug>
      - data_dir + Windows (Git Bash / native): LOCALAPPDATA for data/state,
        APPDATA for config
      - data_dir + Linux: XDG_DATA_HOME / XDG_CONFIG_HOME / XDG_STATE_HOME
      - home base (OpenClaw): $HOME/<install_relative_path> on every platform
    """
    layout = agent.get("install_layout") or {}
    install_base = (layout.get("install_base") or "").strip()
    install_relative_path = (layout.get("install_relative_path") or "").strip()
    slug = (layout.get("config_slug") or layout.get("state_slug") or "").strip()
    agent_type = (agent.get("agent_type") or "").strip()

    home = Path.home()

    if install_base == "home":
        # OpenClaw layout: everything under $HOME/<install_relative_path>.
        install_root = home / install_relative_path
        data_home = install_root
        config_home = install_root
        state_home = install_root / "state"
        return {
            "install_root": str(install_root),
            "data_home": str(data_home),
            "config_home": str(config_home),
            "state_home": str(state_home),
            "config_json": "",
            "psk_path": str(state_home / "edamame-mcp.psk"),
            "mcp_snippet_path": "",
        }

    if install_base != "data_dir":
        raise ValueError(f"unknown install_base: {install_base!r}")

    if not slug:
        raise ValueError(
            f"agent {agent_type!r}: install_layout must define config_slug or state_slug"
        )

    if _is_darwin():
        base = home / "Library" / "Application Support" / slug
        data_home = base
        config_home = base
        state_home = base / "state"
    elif _is_windows():
        local_appdata_env = os.environ.get("LOCALAPPDATA")
        appdata_env = os.environ.get("APPDATA")
        local_appdata = (
            Path(local_appdata_env) if local_appdata_env else home / "AppData" / "Local"
        )
        appdata = Path(appdata_env) if appdata_env else home / "AppData" / "Roaming"
        data_home = local_appdata / slug
        config_home = appdata / slug
        state_home = local_appdata / slug / "state"
    else:
        xdg_data_env = os.environ.get("XDG_DATA_HOME")
        xdg_config_env = os.environ.get("XDG_CONFIG_HOME")
        xdg_state_env = os.environ.get("XDG_STATE_HOME")
        xdg_data = Path(xdg_data_env) if xdg_data_env else home / ".local" / "share"
        xdg_config = Path(xdg_config_env) if xdg_config_env else home / ".config"
        xdg_state = Path(xdg_state_env) if xdg_state_env else home / ".local" / "state"
        data_home = xdg_data / slug
        config_home = xdg_config / slug
        state_home = xdg_state / slug

    install_root = data_home / "current"
    mcp_snippet_name = _MCP_SNIPPET_NAME.get(agent_type, "")
    mcp_snippet_path = config_home / mcp_snippet_name if mcp_snippet_name else None

    return {
        "install_root": str(install_root),
        "data_home": str(data_home),
        "config_home": str(config_home),
        "state_home": str(state_home),
        "config_json": str(config_home / "config.json"),
        "psk_path": str(state_home / "edamame-mcp.psk"),
        "mcp_snippet_path": str(mcp_snippet_path) if mcp_snippet_path else "",
    }


def iter_agents(registry: Dict) -> List[Dict]:
    agents: List[Dict] = []
    for agent in registry.get("agents", []):
        enriched = dict(agent)
        enriched["sort_order"] = int(agent.get("sort_order") or 0)
        enriched["repo_path"] = str(resolve_repo_path(agent))
        agents.append(enriched)
    agents.sort(key=lambda a: (a["sort_order"], a["display_name"]))
    return agents


def iter_intent_agents(registry: Dict) -> List[Dict]:
    agents: List[Dict] = []
    for agent in iter_agents(registry):
        e2e = agent.get("e2e") or {}
        intent_script = e2e.get("intent_script")
        if not intent_script:
            continue
        repo_path = Path(agent["repo_path"])
        agents.append(
            {
                "agent_type": agent["agent_type"],
                "display_name": agent["display_name"],
                "repo_name": agent["repo_name"],
                "sort_order": agent["sort_order"],
                "repo_path": agent["repo_path"],
                "repo_env_var": e2e.get("repo_env_var"),
                "intent_script": str(repo_path / intent_script),
                "intent_timeout_seconds": int(e2e.get("intent_timeout_seconds") or 900),
            }
        )
    return agents


def cmd_types(_: argparse.Namespace) -> int:
    registry = load_registry()
    types = [agent["agent_type"] for agent in iter_agents(registry)]
    print(json.dumps(types))
    return 0


def cmd_get_agent(args: argparse.Namespace) -> int:
    registry = load_registry()
    for agent in iter_agents(registry):
        if agent["agent_type"] == args.agent_type:
            print(json.dumps(agent))
            return 0
    print(f"unknown agent_type: {args.agent_type}", file=sys.stderr)
    return 1


def cmd_list_intent(_: argparse.Namespace) -> int:
    print(json.dumps(iter_intent_agents(load_registry())))
    return 0


def cmd_resolve_paths(args: argparse.Namespace) -> int:
    registry = load_registry()
    for agent in iter_agents(registry):
        if agent["agent_type"] == args.agent_type:
            try:
                print(json.dumps(resolve_install_paths(agent)))
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 1
            return 0
    print(f"unknown agent_type: {args.agent_type}", file=sys.stderr)
    return 1


def cmd_validate(_: argparse.Namespace) -> int:
    registry = load_registry()
    registry_root = registry_dir()
    errors: List[str] = []
    seen_types: Set[str] = set()

    for agent in registry.get("agents", []):
        agent_type = agent["agent_type"]
        if agent_type in seen_types:
            errors.append(f"duplicate agent_type in registry: {agent_type}")
        seen_types.add(agent_type)

        icon_relpath = agent.get("registry_icon_relpath")
        if icon_relpath:
            icon_path = registry_root / icon_relpath
            if not icon_path.is_file():
                errors.append(f"{agent_type}: missing registry icon {icon_path}")

        repo_path = resolve_repo_path(agent)
        if not repo_path.is_dir():
            errors.append(f"{agent_type}: missing repo directory {repo_path}")
            continue

        repo_scripts = agent.get("repo_scripts") or {}
        for field in ("install_unix", "install_windows", "uninstall_unix", "uninstall_windows"):
            relpath = repo_scripts.get(field)
            if relpath and not (repo_path / relpath).is_file():
                errors.append(f"{agent_type}: missing {field} at {repo_path / relpath}")

        healthcheck_relpath = repo_scripts.get("healthcheck_relpath")
        if healthcheck_relpath and not (repo_path / healthcheck_relpath).is_file():
            errors.append(
                f"{agent_type}: missing healthcheck_relpath at {repo_path / healthcheck_relpath}"
            )

        e2e = agent.get("e2e") or {}
        intent_script = e2e.get("intent_script")
        if intent_script and not (repo_path / intent_script).is_file():
            errors.append(f"{agent_type}: missing intent script at {repo_path / intent_script}")

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read the supported-agent registry for E2E harnesses.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("types")
    get_agent = sub.add_parser("get-agent")
    get_agent.add_argument("--agent-type", required=True)
    sub.add_parser("list-intent")
    sub.add_parser("validate")
    resolve_paths = sub.add_parser(
        "resolve-paths",
        help="Resolve platform-aware install paths for an agent (mirrors each plugin's setup/install.sh).",
    )
    resolve_paths.add_argument("--agent-type", required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "types":
        return cmd_types(args)
    if args.command == "get-agent":
        return cmd_get_agent(args)
    if args.command == "list-intent":
        return cmd_list_intent(args)
    if args.command == "validate":
        return cmd_validate(args)
    if args.command == "resolve-paths":
        return cmd_resolve_paths(args)
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
