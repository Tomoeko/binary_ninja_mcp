from __future__ import annotations

import importlib.util
import stat
import subprocess
import sys
import tempfile
import tomllib
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


editor = load_module("codex_config_editor", REPO_ROOT / "scripts" / "codex_config_editor.py")


class CodexConfigEditorTests(unittest.TestCase):
    def _update(self, config: Path) -> bool:
        return editor.update_codex_mcp_entry(
            config,
            "/Applications/Binary Ninja/python3.13",
            [
                str(REPO_ROOT / "scripts" / "run_headless_mcp.py"),
                "--bridge-python",
                str(REPO_ROOT / ".venv" / "bin" / "python3"),
            ],
        )

    def test_quoted_table_multiline_decoys_and_unowned_settings_survive(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            config.write_text(
                'model = "test-model"\n\n'
                '[mcp_servers . "binary_ninja"] # keep-header\n'
                'command = "/old/python"\n'
                'args = ["/old/launcher.py"]\n'
                "startup_timeout_sec = 300\n"
                "tool_timeout_sec = 3600\n"
                'default_tools_approval_mode = "prompt" # keep-policy\n'
                'note = """\n[mcp_servers.fake]\n[desktop]\n"""\n'
                'enabled_tools = ["decompile_function"]\n\n'
                '[mcp_servers.binary_ninja.env]\nTOKEN = "secret" # keep-env\n\n'
                "[mcp_servers.binary_ninja.tools.decompile_function]\n"
                "enabled = true\n\n"
                '[desktop]\nconversationDetailMode = "STEPS"\n',
                encoding="utf-8",
            )

            self.assertTrue(self._update(config))
            first = config.read_bytes()
            first_stat = config.stat()
            parsed = tomllib.loads(first.decode("utf-8"))
            entry = parsed["mcp_servers"]["binary_ninja"]
            self.assertEqual(entry["startup_timeout_sec"], 300)
            self.assertEqual(entry["tool_timeout_sec"], 3600)
            self.assertEqual(entry["default_tools_approval_mode"], "prompt")
            self.assertEqual(entry["env"], {"TOKEN": "secret"})
            self.assertTrue(entry["tools"]["decompile_function"]["enabled"])
            self.assertIn("[mcp_servers.fake]", entry["note"])
            self.assertIn(b"# keep-policy", first)
            self.assertIn(b'TOKEN = "secret" # keep-env', first)

            self.assertFalse(self._update(config))
            second_stat = config.stat()
            self.assertEqual(config.read_bytes(), first)
            self.assertEqual(second_stat.st_ino, first_stat.st_ino)
            self.assertEqual(second_stat.st_mtime_ns, first_stat.st_mtime_ns)

    def test_inline_table_forms_are_updated_without_losing_siblings(self):
        samples = (
            (
                'mcp_servers.binary_ninja = { command = "old", args = ["old"], '
                'enabled = false, default_tools_approval_mode = "decline", '
                'env = { TOKEN = "secret" } }\n',
                "mcp_servers.binary_ninja",
            ),
            (
                'mcp_servers = { other = { command = "other" }, binary_ninja = '
                '{ command = "old", args = ["old"], enabled = false } }\n',
                "mcp_servers",
            ),
        )
        for source, label in samples:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "config.toml"
                config.write_text(source, encoding="utf-8")
                self.assertTrue(self._update(config))
                parsed = tomllib.loads(config.read_text(encoding="utf-8"))
                entry = parsed["mcp_servers"]["binary_ninja"]
                self.assertFalse(entry["enabled"])
                self.assertGreaterEqual(entry["tool_timeout_sec"], 1800)
                if "other" in parsed["mcp_servers"]:
                    self.assertEqual(parsed["mcp_servers"]["other"]["command"], "other")
                else:
                    self.assertEqual(entry["env"], {"TOKEN": "secret"})
                    self.assertEqual(entry["default_tools_approval_mode"], "decline")

    def test_http_transport_entry_is_migrated_to_valid_stdio_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            config.write_text(
                "[mcp_servers.binary_ninja]\n"
                'url = "http://127.0.0.1:9009/mcp"\n'
                'bearer_token = "remove-secret"\n'
                'bearer_token_env_var = "TOKEN_VAR"\n'
                'http_headers = { X-Test = "remove" }\n'
                'env_http_headers = { Authorization = "AUTH_VAR" }\n'
                'http_headers_helper = "/tmp/helper"\n'
                'auth = "oauth"\n'
                'oauth_resource = "binary-ninja"\n'
                'default_tools_approval_mode = "prompt"\n'
                'enabled_tools = ["decompile_function"]\n\n'
                "[mcp_servers.binary_ninja.oauth]\n"
                'scopes = ["analysis"]\n',
                encoding="utf-8",
            )

            self.assertTrue(self._update(config))
            entry = tomllib.loads(config.read_text(encoding="utf-8"))["mcp_servers"]["binary_ninja"]
            for field in editor._HTTP_TRANSPORT_FIELDS:
                self.assertNotIn(field, entry)
            self.assertEqual(entry["default_tools_approval_mode"], "prompt")
            self.assertEqual(entry["enabled_tools"], ["decompile_function"])
            self.assertIn("command", entry)
            self.assertIn("args", entry)

    def test_crlf_and_relative_config_symlink_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_directory = root / "dotfiles"
            real_directory.mkdir()
            target = real_directory / "config.toml"
            target.write_bytes(
                b'model = "x"\r\n\r\n[mcp_servers.binary_ninja]\r\n'
                b'command = "old"\r\nargs = ["old"]\r\n'
            )
            target.chmod(0o640)
            codex_home = root / "codex"
            codex_home.mkdir()
            config = codex_home / "config.toml"
            config.symlink_to(Path("..") / "dotfiles" / "config.toml")

            self.assertTrue(self._update(config))
            self.assertTrue(config.is_symlink())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
            data = target.read_bytes()
            self.assertNotIn(b"\n", data.replace(b"\r\n", b""))
            entry = tomllib.loads(data.decode("utf-8"))["mcp_servers"]["binary_ninja"]
            self.assertEqual(entry["startup_timeout_sec"], 45)
            self.assertEqual(entry["tool_timeout_sec"], 1800)

    @unittest.skipUnless(
        sys.platform == "darwin" and Path("/usr/bin/xattr").is_file(),
        "macOS extended attributes unavailable",
    )
    def test_macos_extended_attributes_survive_atomic_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            config.write_text(
                '[mcp_servers.binary_ninja]\ncommand = "old"\nargs = ["old"]\n',
                encoding="utf-8",
            )
            subprocess.run(
                ["/usr/bin/xattr", "-w", "com.example.binary-ninja-mcp", "preserve", config],
                check=True,
            )

            self.assertTrue(self._update(config))
            value = subprocess.run(
                ["/usr/bin/xattr", "-p", "com.example.binary-ninja-mcp", config],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            self.assertEqual(value, "preserve")

    def test_hard_link_identity_is_never_silently_broken(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            alias = Path(directory) / "config-alias.toml"
            original = '[mcp_servers.binary_ninja]\ncommand = "old"\nargs = ["old"]\n'
            config.write_text(original, encoding="utf-8")
            alias.hardlink_to(config)

            with self.assertRaisesRegex(RuntimeError, "hard-linked"):
                self._update(config)
            self.assertEqual(config.read_text(encoding="utf-8"), original)
            self.assertEqual(alias.read_text(encoding="utf-8"), original)

    def test_new_config_is_private_and_does_not_force_approval_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "new-codex-home" / "config.toml"
            self.assertTrue(self._update(config))
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
            entry = tomllib.loads(config.read_text(encoding="utf-8"))["mcp_servers"]["binary_ninja"]
            self.assertNotIn("default_tools_approval_mode", entry)

    def test_invalid_toml_and_scalar_conflicts_fail_without_writing(self):
        samples = (
            "[broken\n",
            'mcp_servers.binary_ninja = "not-a-table"\n',
        )
        for source in samples:
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                config = Path(directory) / "config.toml"
                config.write_text(source, encoding="utf-8")
                original = config.read_bytes()
                with self.assertRaises(RuntimeError):
                    self._update(config)
                self.assertEqual(config.read_bytes(), original)

    def test_dangling_config_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            config.symlink_to("missing.toml")
            with self.assertRaisesRegex(RuntimeError, "dangling"):
                self._update(config)
            self.assertTrue(config.is_symlink())

    def test_noncooperating_pre_replace_writer_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            original = '[mcp_servers.binary_ninja]\ncommand = "old"\nargs = ["old"]\n'
            external = f"{original}external_change = true\n"
            config.write_text(original, encoding="utf-8")
            real_chmod = editor.os.chmod

            def inject_external_write(path, mode):
                real_chmod(path, mode)
                config.write_text(external, encoding="utf-8")

            with (
                mock.patch.object(editor.os, "chmod", side_effect=inject_external_write),
                self.assertRaisesRegex(RuntimeError, "concurrently"),
            ):
                self._update(config)

            self.assertEqual(config.read_text(encoding="utf-8"), external)

    def test_schema_validation_failure_happens_before_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.toml"
            original = '[mcp_servers.binary_ninja]\ncommand = "old"\nargs = ["old"]\n'
            config.write_text(original, encoding="utf-8")

            def reject(_candidate: bytes) -> None:
                raise RuntimeError("schema rejected")

            with self.assertRaisesRegex(RuntimeError, "schema rejected"):
                editor.update_codex_mcp_entry(config, "/new/python", ["new"], reject)
            self.assertEqual(config.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
