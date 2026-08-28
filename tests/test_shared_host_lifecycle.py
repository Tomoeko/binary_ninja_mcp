from __future__ import annotations

import http.client
import json
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from bridge import shared_host


def make_config(root: Path) -> shared_host.SharedHostConfig:
    return shared_host.SharedHostConfig(
        host_python="/host/python",
        bn_python_path=root / "bn-python",
        bind_host="127.0.0.1",
        bind_port=0,
        startup_timeout=45.0,
        idle_timeout=1.0,
        recovery_timeout=1.0,
        fingerprint="a" * 64,
        runtime_directory=root / "runtime-root" / "runtime",
    )


def make_record(instance: str = "instance-12345678", pid: int = 123) -> shared_host.HostRecord:
    return shared_host.HostRecord(
        shared_host.HostEndpoint("127.0.0.1", 45678, instance),
        pid,
        "t" * 43,
        "a" * 64,
        True,
    )


class SharedHostLifecycleTests(unittest.TestCase):
    def test_lease_is_non_inherited_and_scanner_tracks_its_lifetime(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            lease = shared_host.create_client_lease(config)
            try:
                self.assertFalse(shared_host.os.get_inheritable(lease.file.fileno()))
                self.assertEqual(shared_host.active_client_leases(config.lease_directory), 1)
            finally:
                lease.close()
            self.assertEqual(shared_host.active_client_leases(config.lease_directory), 0)

    def test_first_lease_after_dead_host_discards_the_stale_session_epoch(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            old_lease = shared_host.create_client_lease(config)
            shared_host._write_host_record(config, make_record())
            shared_host._atomic_json_write(
                config.session_file,
                [{"filepath": "/stale/large.bin", "view_id": 1}],
            )
            old_lease.close()

            with mock.patch.object(shared_host, "probe_host_status", return_value="dead"):
                new_lease = shared_host.create_client_lease(config)
            try:
                self.assertFalse(config.state_file.exists())
                self.assertFalse(config.session_file.exists())
                self.assertEqual(shared_host.active_client_leases(config.lease_directory), 1)
            finally:
                new_lease.close()

    def test_first_lease_preserves_a_live_idle_host_session(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            shared_host.ensure_private_directory(config.runtime_directory.parent)
            shared_host.ensure_private_directory(config.runtime_directory)
            shared_host.ensure_private_directory(config.lease_directory)
            shared_host._write_host_record(config, make_record())
            shared_host._atomic_json_write(
                config.session_file,
                [{"filepath": "/live/target.bin", "view_id": 1}],
            )

            for health in ("healthy", "unknown"):
                with (
                    self.subTest(health=health),
                    mock.patch.object(shared_host, "probe_host_status", return_value=health),
                ):
                    lease = shared_host.create_client_lease(config)
                    try:
                        self.assertTrue(config.state_file.exists())
                        self.assertTrue(config.session_file.exists())
                    finally:
                        lease.close()

    def test_journal_rejects_a_missing_stable_view_id_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            with self.assertRaisesRegex(shared_host.SessionRestoreError, "stable view id"):
                shared_host.remember_binary(
                    config,
                    {"filepath": "/target.bin", "analysis_mode": "basic"},
                    None,
                )
            self.assertFalse(config.session_file.exists())

    def test_obsolete_load_callback_cannot_recreate_a_new_epoch_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            shared_host.ensure_private_directory(config.runtime_directory.parent)
            shared_host.ensure_private_directory(config.runtime_directory)
            shared_host.ensure_private_directory(config.lease_directory)
            old = make_record("old-instance-12345678")
            new = make_record("new-instance-12345678", pid=456)
            shared_host._write_host_record(config, old)
            shared_host._atomic_json_write(
                config.session_file,
                [{"filepath": "/old.bin", "view_id": 1}],
            )

            callback_waiting = threading.Event()
            release_callback = threading.Event()
            callback_errors: list[BaseException] = []

            def finish_old_load():
                callback_waiting.set()
                release_callback.wait(timeout=2)
                try:
                    shared_host.remember_binary_for_instance(
                        config,
                        old.endpoint.instance_id,
                        {"filepath": "/late-old.bin", "analysis_mode": "basic"},
                        2,
                    )
                except BaseException as exc:
                    callback_errors.append(exc)

            callback = threading.Thread(target=finish_old_load)
            callback.start()
            self.assertTrue(callback_waiting.wait(timeout=1))
            self.assertTrue(
                shared_host._claim_idle_shutdown(
                    config.lease_directory,
                    config.state_file,
                    old.endpoint.instance_id,
                )
            )
            shared_host._write_host_record(config, new)
            release_callback.set()
            callback.join(timeout=2)

            self.assertFalse(callback.is_alive())
            self.assertEqual(len(callback_errors), 1)
            self.assertIsInstance(callback_errors[0], shared_host.SessionRestoreError)
            self.assertFalse(config.session_file.exists())
            self.assertEqual(
                shared_host._read_host_record(config).endpoint.instance_id,
                new.endpoint.instance_id,
            )

    def test_concurrent_first_use_spawns_exactly_one_host(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            shared_host.ensure_private_directory(config.runtime_directory.parent)
            shared_host.ensure_private_directory(config.runtime_directory)
            record = make_record()
            spawn_count = 0
            count_lock = threading.Lock()

            def spawn(runtime):
                nonlocal spawn_count
                with count_lock:
                    spawn_count += 1
                time.sleep(0.05)
                shared_host._write_host_record(config, record)
                runtime._verified_generation = record.endpoint.instance_id
                return record

            results: list[shared_host.HostRecord] = []
            failures: list[BaseException] = []

            def ensure():
                try:
                    results.append(shared_host.SharedHostRuntime(config).ensure_host())
                except BaseException as exc:
                    failures.append(exc)

            with (
                mock.patch.object(shared_host.SharedHostRuntime, "_spawn_host", spawn),
                mock.patch.object(shared_host, "probe_host_status", return_value="healthy"),
            ):
                threads = [threading.Thread(target=ensure) for _ in range(2)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=2)

            self.assertFalse(failures)
            self.assertEqual(spawn_count, 1)
            self.assertEqual([item.endpoint.instance_id for item in results], [record.endpoint.instance_id] * 2)

    def test_healthy_generation_survives_one_connection_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            shared_host.ensure_private_directory(config.runtime_directory.parent)
            shared_host.ensure_private_directory(config.runtime_directory)
            record = make_record()
            shared_host._write_host_record(config, record)
            runtime = shared_host.SharedHostRuntime(config)
            with (
                mock.patch.object(shared_host, "probe_host_status", return_value="healthy"),
                mock.patch.object(runtime, "_spawn_host") as spawn,
            ):
                recovered = runtime.recover_after_connection_loss(record.endpoint.instance_id)
            self.assertEqual(recovered, record)
            spawn.assert_not_called()

    def test_truncated_health_response_classifies_the_host_as_dead(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        for error in (
            http.client.IncompleteRead(b'{"protocol":', 20),
            http.client.RemoteDisconnected("connection closed"),
        ):
            with (
                self.subTest(error=type(error).__name__),
                mock.patch.object(shared_host, "process_is_alive", return_value=True),
                mock.patch.object(
                    shared_host.DIRECT_HTTP_OPENER,
                    "open",
                    return_value=response,
                ),
                mock.patch.object(shared_host.json, "load", side_effect=error),
            ):
                self.assertEqual(shared_host.probe_host_status(make_record()), "dead")

    def test_missing_earlier_view_fails_closed_before_later_view_loads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(root)
            shared_host.ensure_private_directory(config.runtime_directory.parent)
            shared_host.ensure_private_directory(config.runtime_directory)
            later = root / "later.bin"
            later.write_bytes(b"later")
            config.session_file.write_text(
                json.dumps(
                    [
                        {"filepath": str(root / "missing.bin"), "view_id": 1},
                        {"filepath": str(later), "view_id": 2},
                    ]
                ),
                encoding="utf-8",
            )
            runtime = shared_host.SharedHostRuntime(config)
            with (
                mock.patch.object(shared_host, "_load_binary") as load,
                self.assertRaisesRegex(shared_host.SessionRestoreError, "missing.bin"),
            ):
                runtime._restore_binaries(make_record())
            load.assert_not_called()

    def test_unknown_health_retries_startup_load_once_without_recursion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "startup.bin"
            target.write_bytes(b"target")
            config = replace(make_config(root), startup_binaries=(str(target),))
            shared_host.ensure_private_directory(config.runtime_directory.parent)
            shared_host.ensure_private_directory(config.runtime_directory)
            record = make_record()
            shared_host._write_host_record(config, record)
            runtime = shared_host.SharedHostRuntime(config)
            with (
                mock.patch.object(shared_host, "probe_host_status", return_value="unknown"),
                mock.patch.object(
                    shared_host,
                    "_load_binary",
                    side_effect=shared_host.HostConnectionLost("reset"),
                ) as load,
                self.assertRaises(shared_host.HostConnectionLost),
            ):
                runtime._ensure_startup_binaries(record)
            self.assertEqual(load.call_count, 2)

    def test_shared_host_source_changes_the_runtime_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bridge").mkdir()
            (root / "plugin").mkdir()
            for name in ("binja_mcp_bridge.py", "headless_host.py", "shared_host.py"):
                (root / "bridge" / name).write_text(name, encoding="utf-8")
            (root / "plugin" / "host.py").write_text("plugin", encoding="utf-8")
            with mock.patch.object(shared_host, "REPO_ROOT", root):
                before = shared_host._source_fingerprint("python", root, "127.0.0.1", 0)
                (root / "bridge" / "shared_host.py").write_text("changed", encoding="utf-8")
                after = shared_host._source_fingerprint("python", root, "127.0.0.1", 0)
            self.assertNotEqual(before, after)


if __name__ == "__main__":
    unittest.main()
