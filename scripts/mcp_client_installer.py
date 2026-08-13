import argparse
import json
import os
import shutil
import subprocess
import sys

# Import shared utilities
try:
    # Try relative import first (when run as module)
    from ..plugin.utils.python_detection import (
        copy_python_env,
        create_venv_with_system_python,
        get_python_executable,
    )
except ImportError:
    # Fallback for direct script execution
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugin"))
    from utils.python_detection import (
        copy_python_env,
        create_venv_with_system_python,
        get_python_executable,
    )


# Unique key used in MCP client configs
MCP_SERVER_KEY = "binary_ninja_mcp"
CODEX_MCP_SERVER_KEY = "binary_ninja"
CODEX_SKILL_NAME = "binary-ninja"
CODEX_SKILL_FILES = ("SKILL.md", os.path.join("agents", "openai.yaml"))


def _repo_root() -> str:
    """Return the repository root (one level above this scripts directory)."""
    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def _bridge_entrypoint() -> str:
    return os.path.join(_repo_root(), "bridge", "binja_mcp_bridge.py")


def _headless_entrypoint() -> str:
    return os.path.join(_repo_root(), "scripts", "run_headless_mcp.py")


def _venv_dir() -> str:
    return os.path.join(_repo_root(), ".venv")


def _venv_python() -> str:
    d = _venv_dir()
    if sys.platform == "win32":
        # Always prefer a real Python interpreter for MCP stdio servers.
        # "binaryninja.exe" is an embedded interpreter launcher and does not
        # behave like a normal Python on stdio, causing MCP clients to fail.
        py = os.path.join(d, "Scripts", "python.exe")
        return py
    return os.path.join(d, "bin", "python3")


def _codex_skill_source() -> str:
    return os.path.join(_repo_root(), "skills", CODEX_SKILL_NAME)


def _codex_skill_target(codex_home: str | None = None) -> str:
    if codex_home is None:
        codex_home = os.environ.get("CODEX_HOME")
    if not codex_home:
        codex_home = os.path.join(os.path.expanduser("~"), ".codex")
    root = os.path.abspath(os.path.expanduser(codex_home))
    return os.path.join(root, "skills", CODEX_SKILL_NAME)


def _same_file(left: str, right: str) -> bool:
    if not os.path.isfile(left) or not os.path.isfile(right):
        return False
    if os.path.getsize(left) != os.path.getsize(right):
        return False
    with open(left, "rb") as left_file, open(right, "rb") as right_file:
        return left_file.read() == right_file.read()


def install_codex_skill(
    *,
    uninstall: bool = False,
    quiet: bool = False,
    codex_home: str | None = None,
) -> bool:
    """Install or remove the bundled Codex skill.

    Only files shipped in ``skills/binary-ninja`` are managed. Extra files in
    the destination are preserved during install and uninstall.
    """
    source = _codex_skill_source()
    target = _codex_skill_target(codex_home)
    if not os.path.isdir(source):
        if not quiet:
            print(f"Skipping Codex skill: bundled source not found\n  Source: {source}")
        return False
    if os.path.islink(target):
        raise RuntimeError(f"Refusing to manage symlinked Codex skill directory: {target}")

    changed = False
    if uninstall:
        for relative_path in reversed(CODEX_SKILL_FILES):
            destination = os.path.join(target, relative_path)
            if os.path.islink(destination):
                raise RuntimeError(f"Refusing to remove symlinked Codex skill file: {destination}")
            if os.path.isfile(destination):
                os.remove(destination)
                changed = True

        for directory in (os.path.join(target, "agents"), target):
            try:
                os.rmdir(directory)
            except (FileNotFoundError, OSError):
                pass
    else:
        for relative_path in CODEX_SKILL_FILES:
            source_file = os.path.join(source, relative_path)
            destination = os.path.join(target, relative_path)
            if os.path.islink(destination):
                raise RuntimeError(
                    f"Refusing to overwrite symlinked Codex skill file: {destination}"
                )
            if _same_file(source_file, destination):
                continue
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            shutil.copy2(source_file, destination)
            changed = True

    if not quiet:
        if changed:
            status = "Uninstalled" if uninstall else "Installed"
        else:
            status = "Already absent" if uninstall else "Already current"
        print(f"{status} Codex skill\n  Skill: {target}")
    return changed


def _codex_executable() -> str | None:
    override = os.environ.get("CODEX_CLI_PATH")
    if override:
        candidate = os.path.abspath(os.path.expanduser(override))
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("codex")


def _binary_ninja_python() -> str:
    override = os.environ.get("BINJA_MCP_PYTHON")
    if override:
        candidate = os.path.abspath(os.path.expanduser(override))
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
        raise RuntimeError(
            f"BINJA_MCP_PYTHON is not an executable file: {candidate}"
        )

    candidate = shutil.which("python3.13")
    if candidate:
        return os.path.abspath(candidate)
    raise RuntimeError(
        "Binary Ninja headless mode requires Python 3.13. Install it or set "
        "BINJA_MCP_PYTHON to its absolute executable path."
    )


def _validate_codex_runtime(host_python: str, bridge_python: str) -> None:
    checks = (
        (
            [host_python, _headless_entrypoint(), "--check"],
            "Binary Ninja headless runtime",
        ),
        (
            [
                bridge_python,
                "-c",
                "import requests; import importlib.util; "
                "assert (importlib.util.find_spec('mcp.server.fastmcp') or "
                "importlib.util.find_spec('mcp.server.mcpserver'))",
            ],
            "MCP bridge runtime",
        ),
    )
    for command, description in checks:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if result.returncode == 0:
            continue
        output = "\n".join(
            value.strip()
            for value in (result.stdout, result.stderr)
            if value.strip()
        )
        raise RuntimeError(
            f"{description} validation failed (exit {result.returncode}): {output}"
        )


def install_codex_mcp_server(
    *,
    uninstall: bool = False,
    quiet: bool = False,
    codex_home: str | None = None,
) -> bool:
    """Install the restart-safe headless server in Codex's TOML configuration.

    Use ``codex mcp`` instead of editing TOML directly. This keeps installation
    compatible with Codex configuration schema changes and makes repeated
    installs idempotently replace stale paths.
    """
    codex = _codex_executable()
    if not codex:
        if not quiet:
            print("Skipping Codex MCP server: codex executable not found")
        return False

    command = [codex, "mcp", "remove" if uninstall else "add", CODEX_MCP_SERVER_KEY]
    if not uninstall:
        bridge_python = os.path.abspath(ensure_local_venv())
        host_python = _binary_ninja_python()
        _validate_codex_runtime(host_python, bridge_python)
        command.extend(
            [
                "--",
                host_python,
                _headless_entrypoint(),
                "--bridge-python",
                bridge_python,
            ]
        )

    environment = os.environ.copy()
    if codex_home:
        environment["CODEX_HOME"] = os.path.abspath(os.path.expanduser(codex_home))
    result = subprocess.run(
        command,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    output = "\n".join(
        value.strip() for value in (result.stdout, result.stderr) if value.strip()
    )
    if result.returncode != 0:
        if uninstall and "not found" in output.lower():
            return False
        raise RuntimeError(
            f"Codex MCP configuration failed (exit {result.returncode}): {output}"
        )

    if not quiet:
        action = "Uninstalled" if uninstall else "Installed"
        print(f"{action} Codex MCP server\n  Server: {CODEX_MCP_SERVER_KEY}")
    return True


def ensure_local_venv() -> str:
    """Create a local venv under the plugin root if missing and return its python."""
    vdir = _venv_dir()
    req = os.path.join(_repo_root(), "bridge", "requirements.txt")

    try:
        py = create_venv_with_system_python(vdir, req if os.path.exists(req) else None)
        return py if os.path.exists(py) else get_python_executable()
    except Exception:
        return get_python_executable()


# Note: get_python_executable and copy_python_env are now imported from utils.python_detection


def print_mcp_config():
    """Print a generic MCP config snippet users can copy to unsupported clients."""
    mcp_config = {
        "command": ensure_local_venv(),
        "args": [
            _bridge_entrypoint(),
        ],
        "timeout": 1800,
        "disabled": False,
    }
    env = {}
    if copy_python_env(env):
        mcp_config["env"] = env
    print(json.dumps({"mcpServers": {MCP_SERVER_KEY: mcp_config}}, indent=2))


def _config_targets() -> dict[str, tuple[str, str]]:
    """Return supported MCP client config locations per platform.

    Value is (config_dir, filename).
    """
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        appdata = os.getenv("APPDATA") or os.path.join(home, "AppData", "Roaming")
        return {
            "Cline": (
                os.path.join(
                    appdata, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    appdata,
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (os.path.join(appdata, "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(home, ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(home, ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (home, ".claude.json"),
            "LM Studio": (os.path.join(home, ".lmstudio"), "mcp.json"),
        }
    elif sys.platform == "darwin":
        return {
            "Cline": (
                os.path.join(
                    home,
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    home,
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(home, "Library", "Application Support", "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(home, ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(home, ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (home, ".claude.json"),
            "LM Studio": (os.path.join(home, ".lmstudio"), "mcp.json"),
        }
    elif sys.platform == "linux":
        return {
            "Cline": (
                os.path.join(
                    home,
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    home,
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            # Claude not supported on Linux
            "Cursor": (os.path.join(home, ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(home, ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (home, ".claude.json"),
            "LM Studio": (os.path.join(home, ".lmstudio"), "mcp.json"),
        }
    else:
        return {}


def install_mcp_servers(
    *, uninstall: bool = False, quiet: bool = False, env: dict[str, str] | None = None
) -> int:
    """Install or remove MCP server entries for supported clients.

    Returns the number of configs modified.
    """
    env = {} if env is None else dict(env)
    targets = _config_targets()
    if not targets:
        if not quiet:
            print(f"Unsupported platform: {sys.platform}")
        return 0

    installed = 0
    for name, (config_dir, config_file) in targets.items():
        config_path = os.path.join(config_dir, config_file)
        action_word = "uninstall" if uninstall else "installation"

        if not os.path.exists(config_dir):
            if not quiet:
                print(f"Skipping {name} {action_word}\n  Config: {config_path} (not found)")
            continue

        if not os.path.exists(config_path):
            config: dict = {}
        else:
            try:
                with open(config_path, encoding="utf-8") as f:
                    data = f.read().strip()
                    config = json.loads(data) if data else {}
            except json.decoder.JSONDecodeError:
                if not quiet:
                    print(f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)")
                continue

        config.setdefault("mcpServers", {})
        mcp_servers = config["mcpServers"]

        if uninstall:
            if MCP_SERVER_KEY not in mcp_servers:
                if not quiet:
                    print(f"Skipping {name} uninstall\n  Config: {config_path} (not installed)")
                continue
            del mcp_servers[MCP_SERVER_KEY]
        else:
            # Preserve any existing env overrides for this server
            if MCP_SERVER_KEY in mcp_servers:
                for key, value in mcp_servers[MCP_SERVER_KEY].get("env", {}).items():
                    env[key] = value

            bridge = _bridge_entrypoint()
            if copy_python_env(env) and not quiet:
                print("[WARNING] Custom Python environment variables detected")

            server_cfg = {
                "command": ensure_local_venv(),
                "args": [bridge],
                "timeout": 1800,
                "disabled": False,
            }
            if env:
                server_cfg["env"] = env
            mcp_servers[MCP_SERVER_KEY] = server_cfg

        # Write back
        os.makedirs(config_dir, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        if not quiet:
            print(
                ("Uninstalled" if uninstall else "Installed")
                + f" {name} MCP server (restart required)\n  Config: {config_path}"
            )
        installed += 1

    if not uninstall and installed == 0 and not quiet:
        print("No MCP servers installed. For unsupported MCP clients, use the following config:\n")
        print_mcp_config()

    return installed


def main():
    parser = argparse.ArgumentParser(
        description="Binary Ninja MCP Max - MCP Client Installer (CLI)"
    )
    parser.add_argument(
        "--install", action="store_true", help="Install MCP server entries for supported clients"
    )
    parser.add_argument(
        "--uninstall", action="store_true", help="Remove MCP server entries from supported clients"
    )
    parser.add_argument("--config", action="store_true", help="Print generic MCP config JSON")
    parser.add_argument("--quiet", action="store_true", help="Reduce output noise")
    args = parser.parse_args()

    if args.install and args.uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if args.config:
        print_mcp_config()
        return

    if args.uninstall:
        install_mcp_servers(uninstall=True, quiet=args.quiet)
        install_codex_mcp_server(uninstall=True, quiet=args.quiet)
        install_codex_skill(uninstall=True, quiet=args.quiet)
        # Also remove auto-setup sentinel so the plugin can re-run setup later
        sentinel = os.path.join(_repo_root(), ".mcp_auto_setup_done")
        try:
            os.remove(sentinel)
            if not args.quiet:
                print(f"Removed auto-setup marker: {sentinel}")
        except FileNotFoundError:
            pass
        except Exception as e:
            if not args.quiet:
                print(f"Warning: failed to remove auto-setup marker: {e}")
        return

    # Default action is install if no flag is provided
    if args.install or (not args.uninstall and not args.config):
        install_mcp_servers(quiet=args.quiet)
        install_codex_mcp_server(quiet=args.quiet)
        install_codex_skill(quiet=args.quiet)


if __name__ == "__main__":
    main()
