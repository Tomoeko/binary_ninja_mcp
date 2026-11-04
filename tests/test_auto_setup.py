from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "binary_ninja_mcp_auto_setup_fixture"
package = types.ModuleType(PACKAGE)
package.__path__ = [str(REPO_ROOT / "plugin" / "utils")]
sys.modules[PACKAGE] = package


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


auto_setup = load_module(f"{PACKAGE}.auto_setup", REPO_ROOT / "plugin/utils/auto_setup.py")
editor = load_module("auto_setup_config_editor", REPO_ROOT / "scripts/codex_config_editor.py")


class CodexAutoSetupTests(unittest.TestCase):
    def _register(self, codex_home, *, required=True):
        editor.update_codex_mcp_entry(
            codex_home / "config.toml",
            sys.executable,
            [str(REPO_ROOT / "scripts/run_headless_mcp.py")],
        )
        if not required:
            config = codex_home / "config.toml"
            config.write_text(config.read_text().replace("required = true", "required = false"))
        for relative in ("SKILL.md", "agents/openai.yaml"):
            target = codex_home / "skills/binary-ninja" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPO_ROOT / "skills/binary-ninja" / relative).read_bytes())

    def test_legacy_sentinel_does_not_hide_missing_codex_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            sentinel = home / ".mcp_auto_setup_done"
            sentinel.write_text("ok")
            legacy = home / "claude.json"
            legacy.write_text(json.dumps({"mcpServers": {"binary_ninja_mcp": {"command": "old"}}}))
            original_legacy = legacy.read_bytes()

            def install(command, **_kwargs):
                self.assertEqual(command[2:], ["--install", "--client", "codex", "--quiet"])
                self._register(home)
                return mock.Mock(returncode=0, stdout="", stderr="")

            with (
                mock.patch.dict(auto_setup.os.environ, {"CODEX_HOME": str(home)}),
                mock.patch.object(auto_setup, "_sentinel_path", return_value=str(sentinel)),
                mock.patch.object(
                    auto_setup, "_targets", return_value={"Claude": (str(home), legacy.name)}
                ),
                mock.patch.object(auto_setup, "_ensure_local_venv", return_value=sys.executable),
                mock.patch.object(auto_setup.subprocess, "run", side_effect=install) as run,
            ):
                self.assertEqual(auto_setup.install_mcp_clients(), 1)
                self.assertEqual(auto_setup.install_mcp_clients(), 0)
                run.assert_called_once()
            self.assertEqual(legacy.read_bytes(), original_legacy)
            self.assertEqual(sentinel.read_text(), "ok")

    def test_missing_or_stale_skill_is_repaired_even_with_a_registered_server(self):
        for stale in (None, "old skill"):
            with self.subTest(stale=stale), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                self._register(home)
                target = home / "skills/binary-ninja/SKILL.md"
                if stale is None:
                    target.unlink()
                else:
                    target.write_text(stale)
                with (
                    mock.patch.dict(auto_setup.os.environ, {"CODEX_HOME": str(home)}),
                    mock.patch.object(
                        auto_setup, "_ensure_local_venv", return_value=sys.executable
                    ),
                    mock.patch.object(auto_setup.subprocess, "run") as run,
                ):
                    run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
                    self.assertEqual(auto_setup._install_codex_client(True), 1)
                    run.assert_called_once()

    def test_explicit_optional_policy_does_not_cause_reinstall_on_every_load(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            self._register(home, required=False)
            with (
                mock.patch.dict(auto_setup.os.environ, {"CODEX_HOME": str(home)}),
                mock.patch.object(auto_setup.subprocess, "run") as run,
            ):
                self.assertEqual(auto_setup._install_codex_client(True), 0)
                run.assert_not_called()

    def test_failed_install_is_reported_and_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.dict(auto_setup.os.environ, {"CODEX_HOME": directory}),
                mock.patch.object(auto_setup, "_ensure_local_venv", return_value=sys.executable),
                mock.patch.object(auto_setup.subprocess, "run") as run,
                self.assertLogs(auto_setup.__name__, level="WARNING") as logs,
            ):
                run.return_value = mock.Mock(
                    returncode=1, stdout="", stderr="native runtime unavailable"
                )
                self.assertEqual(auto_setup._install_codex_client(True), 0)
                self.assertEqual(auto_setup._install_codex_client(True), 0)
                self.assertEqual(run.call_count, 2)
                self.assertIn("native runtime unavailable", logs.output[0])

    def test_no_codex_home_does_not_create_an_unrequested_install(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.dict(
                    auto_setup.os.environ, {"CODEX_HOME": str(Path(directory) / "missing")}
                ),
                mock.patch.object(auto_setup.subprocess, "run") as run,
            ):
                self.assertEqual(auto_setup._install_codex_client(True), 0)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
