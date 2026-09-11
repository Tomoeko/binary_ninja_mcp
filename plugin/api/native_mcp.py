"""Headless compatibility dispatcher for Binary Ninja 6's native MCP model.

Binary Ninja Personal includes the native MCP implementation in the GUI, but
does not ship the standalone ``binaryninja_mcp`` executable.  This module maps
the same tool vocabulary onto the repository's isolated Python-API host so the
native model remains available without starting the GUI.
"""

from __future__ import annotations

import base64
import os
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import binaryninja as bn

from ..core.binary_operations import BinaryOperations
from .native_mcp_common import NativeMcpError, json_safe, paginate
from .native_mcp_editing import EDITING_TOOLS, dispatch_editing
from .native_mcp_inspection import INSPECTION_TOOLS, dispatch_inspection

NATIVE_TARGET_FREE_TOOLS = frozenset(
    {
        "bn_binary_view_get_active",
        "bn_binary_view_list",
        "bn_binary_view_set_active",
        "bn_open_item_close",
        "bn_open_item_list",
        "bn_open_item_open",
        "bn_open_item_save",
        "bn_project_file_list",
        "bn_project_file_open",
    }
)
NATIVE_V6_COMPAT_BUILD = "6.0.10601"
_LIFECYCLE_TOOLS = NATIVE_TARGET_FREE_TOOLS | {"bn_binary_view_info"}
_NATIVE_V6_BACKEND_TOOLS = _LIFECYCLE_TOOLS | EDITING_TOOLS | INSPECTION_TOOLS
NATIVE_V6_BACKEND_TOOL_NAMES = frozenset(_NATIVE_V6_BACKEND_TOOLS)
NATIVE_V6_TOOL_COUNT = len(_NATIVE_V6_BACKEND_TOOLS)

if (
    (_LIFECYCLE_TOOLS & EDITING_TOOLS)
    or (_LIFECYCLE_TOOLS & INSPECTION_TOOLS)
    or (EDITING_TOOLS & INSPECTION_TOOLS)
    or NATIVE_V6_TOOL_COUNT != 75
):
    raise RuntimeError("Binary Ninja 6 compatibility backend must implement 75 distinct tools")


class NativeMcpCompat:
    """Dispatch the Binary Ninja 6 native tool vocabulary in a headless host."""

    def __init__(self, binary_ops: BinaryOperations):
        self.binary_ops = binary_ops
        self._projects: dict[str, Any] = {}
        self._project_paths: dict[str, str] = {}
        self._recommended_view_types: dict[str, str] = {}

    @staticmethod
    def _arguments(arguments: object) -> dict[str, object]:
        if not isinstance(arguments, Mapping):
            raise NativeMcpError("invalid_params", "Tool arguments must be a JSON object")
        return {str(key): value for key, value in arguments.items()}

    def dispatch(self, tool: str, arguments: object) -> object:
        args = self._arguments(arguments)
        if tool in _LIFECYCLE_TOOLS:
            return json_safe(self._dispatch_lifecycle(tool, args))
        bv = self.binary_ops.current_view
        if bv is None:
            raise NativeMcpError(
                "no_active_binary_view",
                "No active Binary Ninja binary view is selected",
            )
        if tool in EDITING_TOOLS:
            return json_safe(dispatch_editing(tool, args, bv))
        return json_safe(dispatch_inspection(tool, args, bv))

    def select_target(self, handle: str) -> bool:
        """Select a stable native BinaryView handle for HTTP request scoping."""
        candidate = self._candidate_parts(handle)
        if candidate is None:
            return self.binary_ops.select_view(handle) is not None
        view_id, view_type_name = candidate
        self._activate_candidate(view_id, view_type_name)
        return True

    def _dispatch_lifecycle(self, tool: str, args: dict[str, object]) -> object:
        handlers = {
            "bn_binary_view_get_active": self._binary_view_get_active,
            "bn_binary_view_info": self._binary_view_info,
            "bn_binary_view_list": self._binary_view_list,
            "bn_binary_view_set_active": self._binary_view_set_active,
            "bn_open_item_close": self._open_item_close,
            "bn_open_item_list": self._open_item_list,
            "bn_open_item_open": self._open_item_open,
            "bn_open_item_save": self._open_item_save,
            "bn_project_file_list": self._project_file_list,
            "bn_project_file_open": self._project_file_open,
        }
        try:
            handler = handlers[tool]
        except KeyError as exc:
            raise NativeMcpError("unknown_tool", f"Unknown native MCP tool: {tool}") from exc
        return handler(args)

    @staticmethod
    def _view_handle(view_id: object) -> str:
        value = str(view_id)
        return value if value.startswith("view:") else f"view:{value}"

    @classmethod
    def _open_handle(cls, view_id: object) -> str:
        return f"open:{cls._view_handle(view_id)}"

    @classmethod
    def _candidate_handle(cls, view_id: object, view_type: str) -> str:
        encoded = base64.urlsafe_b64encode(view_type.encode("utf-8")).decode("ascii").rstrip("=")
        return f"candidate:{cls._view_handle(view_id)}:{encoded}"

    @staticmethod
    def _candidate_parts(handle: object) -> tuple[str, str] | None:
        if not isinstance(handle, str) or not handle.startswith("candidate:view:"):
            return None
        parts = handle.split(":", 3)
        if len(parts) != 4 or not parts[2] or not parts[3]:
            raise NativeMcpError("binary_view_not_found", f"Invalid BinaryView handle {handle!r}")
        try:
            padding = "=" * (-len(parts[3]) % 4)
            view_type = base64.urlsafe_b64decode(parts[3] + padding).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise NativeMcpError(
                "binary_view_not_found", f"Invalid BinaryView handle {handle!r}"
            ) from exc
        if not view_type:
            raise NativeMcpError("binary_view_not_found", f"Invalid BinaryView handle {handle!r}")
        return parts[2], view_type

    @staticmethod
    def _selector_from_handle(handle: object) -> str:
        if not isinstance(handle, str) or not handle.strip():
            raise NativeMcpError("invalid_params", "Expected a non-empty item handle")
        value = handle.strip()
        if value.startswith("open:view:"):
            return value.removeprefix("open:")
        if value.startswith("view:"):
            return value
        raise NativeMcpError("item_not_found", f"No open item with handle {value!r}")

    def _binary_items(self) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for item in self.binary_ops.list_open_binaries():
            view_id = item.get("id", "")
            filename = str(item.get("filename") or "")
            active = bool(item.get("active"))
            resolved = self.binary_ops.lookup_view(self._view_handle(view_id))
            view = resolved[1] if resolved is not None else None
            file_metadata = getattr(view, "file", None)
            modified = bool(getattr(file_metadata, "modified", False)) if file_metadata else False
            analysis_modified = (
                bool(getattr(file_metadata, "analysis_changed", False)) if file_metadata else False
            )
            database_backed = (
                bool(getattr(file_metadata, "has_database", False))
                if file_metadata
                else filename.endswith(".bndb")
            )
            result.append(
                {
                    "handle": self._open_handle(view_id),
                    "kind": "database" if database_backed else "file",
                    "displayName": os.path.basename(filename) or filename,
                    "path": filename,
                    "modified": modified,
                    "analysisModified": analysis_modified,
                    "saveable": database_backed,
                    "databaseBacked": database_backed,
                    "validSavePath": filename if database_backed else None,
                    "active": active,
                }
            )
        return result

    def _project_info(self, handle: str, project: object) -> dict[str, object]:
        path = self._project_paths.get(handle, "")
        return {
            "handle": handle,
            "kind": "project",
            "displayName": str(getattr(project, "name", None) or Path(path).stem),
            "projectPath": path,
            "path": path,
            "modified": False,
            "analysisModified": False,
            "saveable": False,
            "databaseBacked": False,
            "validSavePath": None,
        }

    def _open_item_list(self, args: dict[str, object]) -> object:
        items = self._binary_items()
        items.extend(
            self._project_info(handle, project) for handle, project in self._projects.items()
        )
        return paginate(items, args, item_key="openItems")

    def _open_item_open(self, args: dict[str, object]) -> object:
        raw_path = args.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise NativeMcpError("invalid_params", "Expected non-empty string parameter 'path'")
        path = str(Path(raw_path).expanduser().resolve())
        kind = args.get("kind", "auto")
        if kind not in {"auto", "file", "project"}:
            raise NativeMcpError(
                "invalid_params", "Parameter 'kind' must be auto, file, or project"
            )
        set_active = args.get("setActive", True)
        if not isinstance(set_active, bool):
            raise NativeMcpError("invalid_params", "Parameter 'setActive' must be a boolean")

        is_project = kind == "project" or (
            kind == "auto" and Path(path).suffix.lower() in {".bnpr", ".bnpm"}
        )
        if is_project:
            if not Path(path).exists():
                raise NativeMcpError("open_failed", f"Project does not exist: {path}")
            existing_handle = next(
                (key for key, value in self._project_paths.items() if value == path),
                None,
            )
            if existing_handle is not None:
                project = self._projects[existing_handle]
                info = self._project_info(existing_handle, project)
                return {
                    "openItem": info,
                    "binaryViews": [],
                    "activeBinaryView": self._active_view_info(),
                    "changed": False,
                    "mutation": {
                        "operation": tool_operation("open", path),
                        "undoable": False,
                    },
                    "warnings": [],
                }
            try:
                project = bn.Project.open_project(path)
                if not bool(getattr(project, "is_open", False)) and not project.open():
                    raise RuntimeError("Binary Ninja rejected the project")
            except Exception as exc:
                raise NativeMcpError("open_failed", f"Failed to open project {path!r}") from exc
            handle = f"project:{uuid.uuid4().hex}"
            self._projects[handle] = project
            self._project_paths[handle] = path
            info = self._project_info(handle, project)
            return {
                "openItem": info,
                "binaryViews": [],
                "activeBinaryView": self._active_view_info(),
                "changed": True,
                "mutation": {"operation": tool_operation("open", path), "undoable": False},
                "warnings": [],
            }

        if not Path(path).is_file():
            raise NativeMcpError("open_failed", f"File does not exist: {path}")
        previous_active = self._active_view_info()
        already_loaded = self.binary_ops.owns_path(path)
        warnings: list[dict[str, str]] = []
        try:
            if already_loaded:
                resolved = self.binary_ops.lookup_view(path)
                if resolved is None:
                    raise RuntimeError("Resident BinaryView could not be resolved")
                selected, view = resolved
                view_id = str(selected["id"])
            else:
                view = self.binary_ops.load_binary(path, analysis_mode="full")
                view_id = self.binary_ops.register_view(view)
            if set_active:
                self.binary_ops.select_view(self._view_handle(view_id))
            elif not self._restore_active(previous_active):
                warnings.append(
                    {
                        "code": "active_view_not_preserved",
                        "message": "The prior active BinaryView was no longer available.",
                    }
                )
        except Exception as exc:
            raise NativeMcpError(
                "open_failed", f"Failed to open file or database {path!r}"
            ) from exc
        open_item = next(
            item for item in self._binary_items() if item["handle"] == self._open_handle(view_id)
        )
        active_after_open = self._active_view_info()
        self._recommended_view_types.setdefault(str(view_id), self._view_type_name(view))
        binary_views = self._view_candidates(view_id, view, active_after_open)
        return {
            "openItem": open_item,
            "binaryViews": binary_views,
            "activeBinaryView": active_after_open,
            "changed": not already_loaded,
            "mutation": {
                "operation": tool_operation("open", path),
                "before": None,
                "after": open_item,
                "undoable": False,
            },
            "warnings": warnings,
        }

    def _resolve_project(self, handle: object) -> tuple[str, object]:
        if not isinstance(handle, str) or handle not in self._projects:
            raise NativeMcpError("item_not_found", f"No open project with handle {handle!r}")
        return handle, self._projects[handle]

    def _resolve_view(self, handle: object) -> tuple[str, object]:
        view_id, view = self._lookup_view(handle)
        self.binary_ops.current_view = view
        return view_id, view

    def _lookup_view(self, handle: object) -> tuple[str, object]:
        selector = self._selector_from_handle(handle)
        resolved = self.binary_ops.lookup_view(selector)
        if resolved is None:
            raise NativeMcpError("binary_view_not_found", f"No binary view with handle {handle!r}")
        selected, view = resolved
        return str(selected["id"]), view

    def _open_item_save(self, args: dict[str, object]) -> object:
        handle = args.get("openItem")
        previous_active = self._active_view_info()
        try:
            view_id, view = self._lookup_view(handle)
            metadata = getattr(view, "file", None)
            saved = False
            warnings: list[dict[str, str]] = []
            if metadata is not None and bool(getattr(metadata, "has_database", False)):
                try:
                    saved = bool(metadata.save_auto_snapshot())
                except Exception as exc:
                    raise NativeMcpError(
                        "save_failed", "Binary Ninja failed to save the database"
                    ) from exc
            else:
                warnings.append(
                    {
                        "code": "no_valid_save_path",
                        "message": (
                            "The open item is not database-backed; source bytes were not "
                            "overwritten."
                        ),
                    }
                )
            item = next(
                (
                    entry
                    for entry in self._binary_items()
                    if entry["handle"] == self._open_handle(view_id)
                ),
                None,
            )
        finally:
            self._restore_active(previous_active)
        return {
            "openItem": item,
            "saved": saved,
            "changed": saved,
            "mutation": {"operation": "save", "before": None, "after": item, "undoable": False},
            "warnings": warnings,
        }

    def _open_item_close(self, args: dict[str, object]) -> object:
        handle = args.get("openItem")
        save_mode = args.get("save", "prompt")
        if save_mode not in {"prompt", "save", "discard"}:
            raise NativeMcpError(
                "invalid_params", "Parameter 'save' must be prompt, save, or discard"
            )
        if isinstance(handle, str) and handle.startswith("project:"):
            key, project = self._resolve_project(handle)
            try:
                closed = bool(project.close())
            except Exception as exc:
                raise NativeMcpError(
                    "close_failed", "Binary Ninja failed to close the project"
                ) from exc
            if closed:
                self._projects.pop(key, None)
                self._project_paths.pop(key, None)
            return {
                "closed": closed,
                "openItem": None if closed else self._project_info(key, project),
                "changed": closed,
                "mutation": {"operation": "close", "undoable": False},
                "warnings": [],
            }

        previous_active = self._active_view_info()
        view_id, view = self._lookup_view(handle)
        target_was_active = bool(
            previous_active and previous_active.get("openItem") == self._open_handle(view_id)
        )
        metadata = getattr(view, "file", None)
        dirty = bool(getattr(metadata, "modified", False)) or bool(
            getattr(metadata, "analysis_changed", False)
        )
        if dirty and save_mode == "prompt":
            raise NativeMcpError(
                "save_required",
                "The headless item has unsaved changes; choose save or discard explicitly",
            )
        if dirty and save_mode == "save":
            result = self._open_item_save({"openItem": handle})
            if not result.get("saved"):
                raise NativeMcpError("save_failed", "The open item could not be saved before close")
        try:
            closed_record = self.binary_ops.close_owned_view(
                self._view_handle(view_id),
                discard=save_mode == "discard" or not dirty,
            )
        except KeyError as exc:
            self._restore_active(previous_active)
            raise NativeMcpError("item_not_found", f"No open item with handle {handle!r}") from exc
        except Exception as exc:
            self._restore_active(previous_active)
            raise NativeMcpError(
                "close_failed", "Binary Ninja failed to close the open item"
            ) from exc
        if not target_was_active:
            self._restore_active(previous_active)
        self._recommended_view_types.pop(str(view_id), None)
        return {
            "closed": True,
            "openItem": None,
            "changed": True,
            "mutation": {
                "operation": "close",
                "before": {"handle": handle, "path": closed_record.get("filepath")},
                "after": None,
                "undoable": False,
            },
            "warnings": [],
        }

    def _view_info(
        self,
        view: object,
        view_id: object,
        *,
        recommended: bool = False,
        created: bool = True,
    ) -> dict[str, object]:
        filename = str(getattr(getattr(view, "file", None), "filename", ""))
        return {
            "handle": self._view_handle(view_id),
            "openItem": self._open_handle(view_id),
            "viewType": str(getattr(view, "view_type", None) or getattr(view, "name", "Mapped")),
            "longName": str(getattr(view, "name", None) or os.path.basename(filename)),
            "created": created,
            "available": True,
            "recommended": recommended,
            "filename": filename,
            "start": hex(int(getattr(view, "start", 0))),
            "end": hex(int(getattr(view, "end", 0))),
            "addressSize": int(getattr(getattr(view, "arch", None), "address_size", 0) or 0),
            "architecture": getattr(getattr(view, "arch", None), "name", None),
            "platform": getattr(getattr(view, "platform", None), "name", None),
        }

    @staticmethod
    def _view_type_name(view: object) -> str:
        return str(getattr(view, "view_type", None) or getattr(view, "name", "Raw"))

    @staticmethod
    def _file_view(metadata: object, view_type: str) -> object | None:
        getter = getattr(metadata, "get_view_of_type", None)
        if not callable(getter):
            return None
        try:
            return getter(view_type)
        except Exception:
            return None

    def _view_candidates(
        self,
        view_id: object,
        view: object,
        active_info: dict[str, object] | None,
    ) -> list[dict[str, object]]:
        metadata = getattr(view, "file", None)
        filename = str(getattr(metadata, "filename", ""))
        current_type = self._view_type_name(view)
        recommended_type = self._recommended_view_types.setdefault(str(view_id), current_type)
        existing = {
            str(name) for name in (getattr(metadata, "existing_views", []) or []) if str(name)
        }
        existing.add(current_type)
        raw = self._file_view(metadata, "Raw")
        if raw is None and current_type == "Raw":
            raw = view

        available = set(existing)
        if raw is not None:
            try:
                view_types = list(bn.BinaryViewType)
            except Exception:
                view_types = []
            for view_type in view_types:
                name = str(getattr(view_type, "name", ""))
                if not name:
                    continue
                try:
                    valid = bool(view_type.is_valid_for_data(raw))
                except Exception:
                    valid = False
                if valid:
                    available.add(name)

        active_filename = str(active_info.get("filename", "")) if active_info else ""
        active_type = str(active_info.get("viewType", "")) if active_info else ""
        result: list[dict[str, object]] = []
        for name in sorted(available, key=lambda item: (item != current_type, item == "Raw", item)):
            created = name in existing
            candidate = self._file_view(metadata, name) if created else None
            if candidate is None and name == current_type:
                candidate = view
            active = filename == active_filename and name == active_type
            model = candidate or raw or view
            info = self._view_info(
                model,
                view_id,
                recommended=name == recommended_type,
                created=created,
            )
            info.update(
                {
                    "handle": self._candidate_handle(view_id, name),
                    "viewType": name,
                    "longName": name,
                    "active": active,
                }
            )
            result.append(info)
        return result

    def _activate_candidate(self, view_id: str, view_type_name: str) -> object:
        resolved = self.binary_ops.lookup_view(self._view_handle(view_id))
        if resolved is None:
            raise NativeMcpError(
                "binary_view_not_found", f"No open item owns BinaryView view:{view_id}"
            )
        _selected, base_view = resolved
        metadata = getattr(base_view, "file", None)
        target = self._file_view(metadata, view_type_name)
        if target is None:
            raw = self._file_view(metadata, "Raw")
            if raw is None and self._view_type_name(base_view) == "Raw":
                raw = base_view
            try:
                view_type = bn.BinaryViewType[view_type_name]
            except Exception as exc:
                raise NativeMcpError(
                    "binary_view_not_found",
                    f"BinaryView type {view_type_name!r} is unavailable",
                ) from exc
            try:
                valid = raw is not None and bool(view_type.is_valid_for_data(raw))
            except Exception:
                valid = False
            if not valid:
                raise NativeMcpError(
                    "binary_view_not_found",
                    f"BinaryView type {view_type_name!r} is not valid for this open item",
                )
            try:
                target = view_type.create(raw)
            except Exception as exc:
                raise NativeMcpError(
                    "open_failed", f"Failed to create BinaryView type {view_type_name!r}"
                ) from exc
            if target is None:
                raise NativeMcpError(
                    "open_failed", f"Failed to create BinaryView type {view_type_name!r}"
                )
            updater = getattr(target, "update_analysis", None)
            if callable(updater):
                updater()
        self.binary_ops.current_view = target
        return target

    def _active_view_info(self) -> dict[str, object] | None:
        view = self.binary_ops.current_view
        if view is None:
            return None
        filename = str(getattr(getattr(view, "file", None), "filename", ""))
        for item in self.binary_ops.list_open_binaries():
            if item.get("filename") == filename:
                view_id = item.get("id", "")
                info = self._view_info(
                    view,
                    view_id,
                    recommended=(
                        self._recommended_view_types.get(str(view_id), self._view_type_name(view))
                        == self._view_type_name(view)
                    ),
                )
                info["handle"] = self._candidate_handle(view_id, self._view_type_name(view))
                info["active"] = True
                return info
        return None

    def _restore_active(self, info: dict[str, object] | None) -> bool:
        if info is None:
            self.binary_ops.current_view = None
            return True
        handle = info.get("handle")
        if not isinstance(handle, str):
            return False
        try:
            return self.select_target(handle)
        except NativeMcpError:
            return False

    def _binary_view_list(self, args: dict[str, object]) -> object:
        requested_item = args.get("openItem")
        views: list[dict[str, object]] = []
        previous_active = self._active_view_info()
        try:
            for item in self.binary_ops.list_open_binaries():
                view_id = item.get("id", "")
                if requested_item not in (None, "", self._open_handle(view_id)):
                    continue
                resolved = self.binary_ops.lookup_view(self._view_handle(view_id))
                view = resolved[1] if resolved is not None else None
                if view is not None:
                    views.extend(self._view_candidates(view_id, view, previous_active))
        finally:
            self._restore_active(previous_active)
        return paginate(views, args, item_key="binaryViews")

    def _binary_view_get_active(self, _args: dict[str, object]) -> object:
        return {"binaryView": self._active_view_info(), "warnings": []}

    def _binary_view_set_active(self, args: dict[str, object]) -> object:
        handle = args.get("binaryView")
        before = self._active_view_info()
        try:
            candidate = self._candidate_parts(handle)
            if candidate is None:
                _view_id, _view = self._resolve_view(handle)
            else:
                _view_id, view_type_name = candidate
                _view = self._activate_candidate(_view_id, view_type_name)
        except Exception:
            self._restore_active(before)
            raise
        after = self._active_view_info()
        return {
            "binaryView": after,
            "openItem": {"handle": after["openItem"]} if after else None,
            "changed": before != after,
            "mutation": {
                "operation": "set_active_binary_view",
                "before": before,
                "after": after,
                "undoable": False,
            },
            "warnings": [],
        }

    def _binary_view_info(self, _args: dict[str, object]) -> object:
        info = self._active_view_info()
        if info is None:
            raise NativeMcpError(
                "no_active_binary_view",
                "No active Binary Ninja binary view is selected",
            )
        return {"binaryView": info, "warnings": []}

    def _project_file_list(self, args: dict[str, object]) -> object:
        handle, project = self._resolve_project(args.get("project"))
        files = []
        for project_file in list(getattr(project, "files", []) or []):
            files.append(
                {
                    "handle": str(getattr(project_file, "id", "")),
                    "project": handle,
                    "projectFile": str(getattr(project_file, "id", "")),
                    "name": str(getattr(project_file, "name", "")),
                    "pathInProject": _call_or_value(project_file, "get_path_in_project"),
                    "pathOnDisk": _call_or_value(project_file, "get_path_on_disk"),
                    "existsOnDisk": bool(
                        Path(str(_call_or_value(project_file, "get_path_on_disk") or "")).is_file()
                    ),
                    "creationTimestamp": getattr(project_file, "creation_timestamp", None),
                }
            )
        result = paginate(files, args, item_key="projectFiles")
        result["project"] = self._project_info(handle, project)
        return result

    def _project_file_open(self, args: dict[str, object]) -> object:
        handle, project = self._resolve_project(args.get("project"))
        project_file_id = args.get("projectFile")
        path_in_project = args.get("pathInProject")
        if bool(project_file_id) == bool(path_in_project):
            raise NativeMcpError(
                "invalid_params",
                "Expected exactly one of 'projectFile' or 'pathInProject'",
            )
        project_file = None
        if project_file_id:
            project_file = project.get_file_by_id(str(project_file_id))
        else:
            matches = list(project.get_files_by_path_in_project(str(path_in_project)))
            if len(matches) > 1:
                raise NativeMcpError(
                    "project_file_ambiguous",
                    f"Multiple project files match path {path_in_project!r}",
                )
            project_file = matches[0] if matches else None
        if project_file is None:
            raise NativeMcpError("project_file_not_found", "No matching project file was found")
        path = _call_or_value(project_file, "get_path_on_disk")
        if not path:
            raise NativeMcpError(
                "open_failed",
                "The selected project file has no path on disk for headless opening",
            )
        opened = self._open_item_open(
            {"path": str(path), "kind": "file", "setActive": args.get("setActive", True)}
        )
        return {
            "project": self._project_info(handle, project),
            "projectFile": {
                "projectFile": str(getattr(project_file, "id", "")),
                "pathInProject": _call_or_value(project_file, "get_path_in_project"),
                "pathOnDisk": path,
            },
            **opened,
        }


def _call_or_value(obj: object, name: str) -> object:
    value = getattr(obj, name, None)
    return value() if callable(value) else value


def tool_operation(operation: str, subject: object) -> str:
    """Return a concise mutation label without exposing implementation state."""
    return f"{operation}:{subject}"


__all__ = [
    "NATIVE_TARGET_FREE_TOOLS",
    "NATIVE_V6_BACKEND_TOOL_NAMES",
    "NATIVE_V6_COMPAT_BUILD",
    "NATIVE_V6_TOOL_COUNT",
    "NativeMcpCompat",
    "NativeMcpError",
]
