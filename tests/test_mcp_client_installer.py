from __future__ import annotations

import importlib.util
import tempfile
import unittest
from unittest import mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


installer = load_module("mcp_client_installer", REPO_ROOT / "scripts" / "mcp_client_installer.py")


class CodexSkillInstallerTests(unittest.TestCase):
    def test_install_is_idempotent_and_updates_managed_files(self):
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory) / "codex"
            self.assertTrue(installer.install_codex_skill(codex_home=str(codex_home), quiet=True))

            source = REPO_ROOT / "skills" / "binary-ninja"
            target = codex_home / "skills" / "binary-ninja"
            for relative_path in installer.CODEX_SKILL_FILES:
                self.assertEqual(
                    (target / relative_path).read_bytes(),
                    (source / relative_path).read_bytes(),
                )

            self.assertFalse(installer.install_codex_skill(codex_home=str(codex_home), quiet=True))
            (target / "SKILL.md").write_text("stale", encoding="utf-8")
            self.assertTrue(installer.install_codex_skill(codex_home=str(codex_home), quiet=True))
            self.assertEqual(
                (target / "SKILL.md").read_bytes(),
                (source / "SKILL.md").read_bytes(),
            )

    def test_uninstall_removes_only_managed_files(self):
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory) / "codex"
            installer.install_codex_skill(codex_home=str(codex_home), quiet=True)
            target = codex_home / "skills" / "binary-ninja"
            extra = target / "notes.txt"
            extra.write_text("preserve", encoding="utf-8")

            self.assertTrue(
                installer.install_codex_skill(
                    uninstall=True, codex_home=str(codex_home), quiet=True
                )
            )
            self.assertEqual(extra.read_text(encoding="utf-8"), "preserve")
            for relative_path in installer.CODEX_SKILL_FILES:
                self.assertFalse((target / relative_path).exists())


class CodexMcpInstallerTests(unittest.TestCase):
    def test_install_uses_codex_cli_and_absolute_headless_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory) / "codex"
            with (
                mock.patch.object(installer, "_codex_executable", return_value="/opt/codex"),
                mock.patch.object(
                    installer, "_binary_ninja_python", return_value="/opt/python3.13"
                ),
                mock.patch.object(
                    installer, "ensure_local_venv", return_value="/tmp/bridge/python"
                ),
                mock.patch.object(installer, "_validate_codex_runtime") as validate,
                mock.patch.object(installer.subprocess, "run") as run,
            ):
                run.return_value = mock.Mock(returncode=0, stdout="ok", stderr="")
                self.assertTrue(
                    installer.install_codex_mcp_server(
                        codex_home=str(codex_home), quiet=True
                    )
                )

            command = run.call_args.args[0]
            self.assertEqual(
                command[:5],
                ["/opt/codex", "mcp", "add", "binary_ninja", "--"],
            )
            self.assertEqual(command[5], "/opt/python3.13")
            self.assertEqual(command[6], str(REPO_ROOT / "scripts" / "run_headless_mcp.py"))
            self.assertEqual(command[7:], ["--bridge-python", "/tmp/bridge/python"])
            validate.assert_called_once_with("/opt/python3.13", "/tmp/bridge/python")
            self.assertEqual(
                run.call_args.kwargs["env"]["CODEX_HOME"], str(codex_home)
            )

    def test_uninstall_removes_only_the_managed_codex_server(self):
        with (
            mock.patch.object(installer, "_codex_executable", return_value="/opt/codex"),
            mock.patch.object(installer.subprocess, "run") as run,
        ):
            run.return_value = mock.Mock(returncode=0, stdout="removed", stderr="")
            self.assertTrue(installer.install_codex_mcp_server(uninstall=True, quiet=True))
        self.assertEqual(
            run.call_args.args[0],
            ["/opt/codex", "mcp", "remove", "binary_ninja"],
        )


if __name__ == "__main__":
    unittest.main()
