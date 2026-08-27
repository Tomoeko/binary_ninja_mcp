from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
    def test_macos_prefers_the_app_cli_used_after_restart(self):
        app_cli = installer.MACOS_CODEX_APP_EXECUTABLES[0]
        with (
            mock.patch.dict(installer.os.environ, {"CODEX_CLI_PATH": ""}),
            mock.patch.object(installer.sys, "platform", "darwin"),
            mock.patch.object(
                installer.os.path,
                "isfile",
                side_effect=lambda path: path == app_cli,
            ),
            mock.patch.object(installer.os, "access", return_value=True),
            mock.patch.object(installer.shutil, "which", return_value="/old/codex"),
        ):
            self.assertEqual(installer._codex_executable(), app_cli)

    def test_existing_venv_installs_missing_or_outdated_editor_dependency(self):
        missing = mock.Mock(returncode=1, stdout="", stderr="missing")
        installed = mock.Mock(returncode=0, stdout="installed", stderr="")
        with mock.patch.object(
            installer.subprocess,
            "run",
            side_effect=[missing, installed],
        ) as run:
            installer._ensure_codex_config_editor_runtime("/tmp/bridge/python")

        self.assertIn("tomlkit.__version__", run.call_args_list[0].args[0][2])
        self.assertEqual(
            run.call_args_list[1].args[0],
            [
                "/tmp/bridge/python",
                "-m",
                "pip",
                "install",
                installer.CODEX_CONFIG_EDITOR_REQUIREMENT,
            ],
        )

    def test_runtime_validation_uses_the_isolating_launcher(self):
        successful = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(
            installer.subprocess,
            "run",
            side_effect=[successful, successful],
        ) as run:
            installer._validate_codex_runtime(
                "/opt/python3.13",
                "/tmp/bridge/python",
            )

        self.assertEqual(
            run.call_args_list[0].args[0],
            [
                "/opt/python3.13",
                str(REPO_ROOT / "scripts" / "run_headless_mcp.py"),
                "--python",
                "/opt/python3.13",
                "--check",
            ],
        )

    def test_install_losslessly_configures_absolute_headless_paths(self):
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
                mock.patch.object(installer, "_ensure_codex_config_editor_runtime") as ensure,
                mock.patch.object(installer, "_validate_codex_runtime") as validate,
                mock.patch.object(
                    installer, "_configure_codex_mcp_entry", return_value=True
                ) as configure,
                mock.patch.object(installer, "_validate_codex_registration") as registration,
            ):
                self.assertTrue(
                    installer.install_codex_mcp_server(codex_home=str(codex_home), quiet=True)
                )

            ensure.assert_called_once_with("/tmp/bridge/python")
            validate.assert_called_once_with("/opt/python3.13", "/tmp/bridge/python")
            configure.assert_called_once_with(
                "/tmp/bridge/python",
                "/opt/python3.13",
                [
                    str(REPO_ROOT / "scripts" / "run_headless_mcp.py"),
                    "--bridge-python",
                    "/tmp/bridge/python",
                ],
                str(codex_home),
                "/opt/codex",
            )
            registration.assert_called_once_with(str(codex_home))

    def test_config_editor_is_invoked_through_the_managed_venv(self):
        with tempfile.TemporaryDirectory() as directory:
            codex_home = Path(directory) / "codex"
            with mock.patch.object(installer.subprocess, "run") as run:
                run.return_value = mock.Mock(returncode=0, stdout="updated\n", stderr="")
                changed = installer._configure_codex_mcp_entry(
                    "/tmp/bridge/python",
                    "/opt/python3.13",
                    ["/repo/run_headless_mcp.py", "--bridge-python", "/tmp/bridge/python"],
                    str(codex_home),
                    "/opt/codex",
                )

            self.assertTrue(changed)
            command = run.call_args.args[0]
            self.assertEqual(command[0], "/tmp/bridge/python")
            self.assertEqual(command[1], str(REPO_ROOT / "scripts" / "codex_config_editor.py"))
            self.assertIn(str(codex_home / "config.toml"), command)
            self.assertEqual(command[-2:], ["--codex-cli", "/opt/codex"])
            self.assertNotIn("mcp add", " ".join(command))
            self.assertEqual(run.call_args.kwargs["timeout"], 180)

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
