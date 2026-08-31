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
    def test_versioned_manifest_prunes_views_but_preserves_id_watermark(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(root)
            shared_host.ensure_private_directory(config.runtime_directory.parent)
            shared_host.ensure_private_directory(config.runtime_directory)
            target = root / "target.bin"
            target.write_bytes(b"target")

            shared_host.replace_binary_session(
                config,
                [
                    {
                        "filepath": str(target),
                        "analysis_mode": "basic",
                        "platform": "",
                        "image_base": "",
                        "view_id": 5,
                    }
                ],
                9,
            )
            snapshot = shared_host._read_session_snapshot(config)
            self.assertEqual([record["view_id"] for record in snapshot.binaries], [5])
            self.assertEqual(snapshot.next_view_id, 9)
            identity = snapshot.binaries[0]["source_identity"]
            info = target.stat()
            self.assertEqual(
                identity,
                {
                    "device": info.st_dev,
                    "inode": info.st_ino,
                    "size": info.st_size,
                    "mtime_ns": info.st_mtime_ns,
                    "ctime_ns": info.st_ctime_ns,
                },
            )

            shared_host.replace_binary_session(config, [], 9)
            empty = shared_host._read_session_snapshot(config)
            self.assertEqual(empty.binaries, [])
            self.assertEqual(empty.next_view_id, 9)

    def test_instance_checkpoint_cannot_rewind_persisted_watermark(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(Path(directory))
            shared_host.ensure_private_directory(config.runtime_directory.parent)
            shared_host.ensure_private_directory(config.runtime_directory)
            shared_host._write_host_record(config, make_record())
            shared_host.replace_binary_session(config, [], 12)

            shared_host.replace_binary_session_for_instance(
                config,
                make_record().endpoint.instance_id,
                [],
                1,
            )

            snapshot = shared_host._read_session_snapshot(config)
            self.assertEqual(snapshot.binaries, [])
            self.assertEqual(snapshot.next_view_id, 12)

    def test_restore_defers_manifest_sync_until_the_complete_batch_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(root)
            shared_host.ensure_private_directory(config.runtime_directory.parent)
            shared_host.ensure_private_directory(config.runtime_directory)
            targets = [root / "one.bin", root / "two.bin"]
            for target in targets:
                target.write_bytes(target.name.encode("ascii"))
            shared_host.replace_binary_session(
                config,
                [
                    {"filepath": str(targets[0]), "view_id": 3},
                    {"filepath": str(targets[1]), "view_id": 8},
                ],
                12,
            )
            original = config.session_file.read_bytes()
            runtime = shared_host.SharedHostRuntime(config)

            with (
                mock.patch.object(
                    shared_host,
                    "_load_binary",
                    side_effect=[
                        {"view_id": 3},
                        RuntimeError("second load failed"),
                    ],
                ) as load,
                mock.patch.object(shared_host, "_sync_binary_inventory") as sync,
                self.assertRaisesRegex(shared_host.SessionRestoreError, "second load failed"),
            ):
                runtime._restore_binaries(make_record())

            self.assertEqual(config.session_file.read_bytes(), original)
            self.assertEqual(load.call_count, 2)
            for call in load.call_args_list:
                self.assertTrue(call.args[1]["suppress_inventory"])
                self.assertEqual(call.args[1]["next_view_id"], 12)
            sync.assert_not_called()

            with (
                mock.patch.object(
                    shared_host,
                    "_load_binary",
                    side_effect=[{"view_id": 3}, {"view_id": 8}],
                ),
                mock.patch.object(shared_host, "_sync_binary_inventory") as sync,
            ):
                runtime._restore_binaries(make_record())
            sync.assert_called_once_with(make_record(), 1740.0, 12)

    def test_empty_restore_still_reserves_and_syncs_the_id_watermark(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(root)
            shared_host.ensure_private_directory(config.runtime_directory.parent)
            shared_host.ensure_private_directory(config.runtime_directory)
            shared_host.replace_binary_session(config, [], 9)
            runtime = shared_host.SharedHostRuntime(config)
            record = make_record()

            with (
                mock.patch.object(shared_host, "_load_binary") as load,
                mock.patch.object(shared_host, "_sync_binary_inventory") as sync,
            ):
                runtime._restore_binaries(record)

            load.assert_not_called()
            sync.assert_called_once_with(record, 1740.0, 9)

    def test_inventory_sync_posts_the_id_watermark(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        with (
            mock.patch.object(
                shared_host.DIRECT_HTTP_OPENER,
                "open",
                return_value=response,
            ) as open_request,
            mock.patch.object(
                shared_host.json,
                "load",
                return_value={"success": True},
            ),
        ):
            shared_host._sync_binary_inventory(make_record(), 3.5, 17)

        request = open_request.call_args.args[0]
        self.assertEqual(json.loads(request.data), {"next_view_id": 17})
        self.assertEqual(open_request.call_args.kwargs["timeout"], 3.5)

    def test_restore_rejects_changed_identity_before_loading_any_view(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(root)
            shared_host.ensure_private_directory(config.runtime_directory.parent)
            shared_host.ensure_private_directory(config.runtime_directory)
            targets = [root / "one.bin", root / "two.bin"]
            for target in targets:
                target.write_bytes(target.name.encode("ascii"))
            shared_host.replace_binary_session(
                config,
                [
                    {"filepath": str(targets[0]), "view_id": 1},
                    {"filepath": str(targets[1]), "view_id": 2},
                ],
                3,
            )
            targets[1].write_bytes(b"changed-after-journal")
            runtime = shared_host.SharedHostRuntime(config)

            with (
                mock.patch.object(shared_host, "_load_binary") as load,
                mock.patch.object(shared_host, "_sync_binary_inventory") as sync,
                self.assertRaisesRegex(shared_host.SessionRestoreError, "changed on disk"),
            ):
                runtime._restore_binaries(make_record())

            load.assert_not_called()
            sync.assert_not_called()

    def test_restore_rechecks_identity_after_each_load(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(root)
            shared_host.ensure_private_directory(config.runtime_directory.parent)
            shared_host.ensure_private_directory(config.runtime_directory)
            target = root / "target.bin"
            target.write_bytes(b"original")
            shared_host.replace_binary_session(
                config,
                [{"filepath": str(target), "view_id": 4}],
                5,
            )
            runtime = shared_host.SharedHostRuntime(config)

            def mutate_during_load(*_args):
                target.write_bytes(b"mutated-during-load")
                return {"view_id": 4}

            with (
                mock.patch.object(
                    shared_host,
                    "_load_binary",
                    side_effect=mutate_during_load,
                ),
                mock.patch.object(shared_host, "_sync_binary_inventory") as sync,
                self.assertRaisesRegex(
                    shared_host.SessionRestoreError,
                    "changed while it was being opened",
                ),
            ):
                runtime._restore_binaries(make_record())

            sync.assert_not_called()

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
            self.assertEqual(
                [item.endpoint.instance_id for item in results], [record.endpoint.instance_id] * 2
            )

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

    def test_cache_limit_changes_host_identity_and_round_trips_to_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bridge").mkdir()
            (root / "plugin").mkdir()
            for name in ("binja_mcp_bridge.py", "headless_host.py", "shared_host.py"):
                (root / "bridge" / name).write_text(name, encoding="utf-8")
            (root / "plugin" / "host.py").write_text("plugin", encoding="utf-8")
            with mock.patch.object(shared_host, "REPO_ROOT", root):
                two = shared_host._source_fingerprint("python", root, "127.0.0.1", 0, 2)
                three = shared_host._source_fingerprint("python", root, "127.0.0.1", 0, 3)
            self.assertNotEqual(two, three)

            rss_variant = shared_host._source_fingerprint("python", root, "127.0.0.1", 0, 3, 8192)
            self.assertNotEqual(three, rss_variant)

            config = replace(
                make_config(root),
                max_open_binaries=3,
                max_rss_mb=8192,
            )
            environment = {}
            config.to_environment(environment)
            with mock.patch.dict(shared_host.os.environ, environment, clear=False):
                decoded = shared_host.SharedHostConfig.from_environment()
            self.assertIsNotNone(decoded)
            self.assertEqual(decoded.max_open_binaries, 3)
            self.assertEqual(decoded.max_rss_mb, 8192)


if __name__ == "__main__":
    unittest.main()
