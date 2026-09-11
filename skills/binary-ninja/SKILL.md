---
name: binary-ninja
description: Analyze native binaries, firmware images, object files, shared libraries, and Binary Ninja databases through the Binary Ninja MCP server. Use for disassembly, decompilation, HLIL/MLIL/LLIL analysis, symbols, strings, types, call graphs, cross-references, data-flow investigation, annotations, renaming, or explicitly requested binary patching with Binary Ninja.
---

# Binary Ninja

Use the `mcp__binary_ninja__*` tools for Binary Ninja analysis. The headless
server exposes both Binary Ninja 6's native `bn_*` vocabulary and the
repository's extended legacy tools. Prefer a native `bn_*` tool when it covers
the operation; use an extended tool for capabilities such as byte patching,
explicit load platform/image-base control, number conversion, or specialized
type-field searches. This integration is headless-only: it never launches,
attaches to, or automates the Binary Ninja GUI.

## Open and identify the target

1. Work only on binaries the user placed in scope. Use an absolute path.
2. Call `get_binary_status`, `list_binaries`, or `bn_open_item_list` before
   opening a new target.
3. Call `open_binary` when the requested target is not already active and you
   need explicit analysis mode, platform, or image-base control. Retain its
   stable legacy `view:N` selector and confirm the filename and loaded state
   with `get_binary_status(binary=<view:N>)`. Use `bn_open_item_open` for the
   Binary Ninja 6 native file/database/project workflow; retain both its
   `openItem` and recommended `binaryView` handles.
4. On every native active-view tool, pass the exact type-qualified
   `binaryView` handle as `binary=<candidate handle>`. On extended legacy tools,
   pass `binary=<view:N selector or absolute filename>`. Explicit targeting is
   mandatory when subagents or concurrent calls may share the MCP server:
   `select_binary` changes legacy mutable state and is not a concurrency
   boundary.
5. Use `convert_number` for base, endian, character, or byte conversions; do
   not perform address-base conversions manually.

Use `list_binaries` to recover a legacy selector for an already-open item.
Prefer its namespaced `view:N` selector or full absolute filename. Bare numeric
ids are intentionally rejected because an internal id can collide with a
sorted ordinal; `ordinal:N` is available for short-lived interactive selection
only. `select_binary` remains available for changing the legacy headless
current analyzed view, but it does not scope later requests when multiple items
are open. No GUI selection is involved. Explicit `binary` arguments are the
authoritative targeting mechanism.

For a native file or database, `openItem` is `open:view:N`. Native
`binaryView` handles are stable, type-qualified candidates of the form
`candidate:view:N:<encoded-view-type>`; recover them with
`bn_binary_view_list` and pass the selected value verbatim through `binary=` on
native active-view tools. The legacy `view:N` value identifies the open item
and its current analyzed view, not a particular native view-type candidate.
`bn_binary_view_set_active` changes that headless current analyzed view and may
create the chosen view type, but it does not scope later concurrent calls;
continue passing the candidate handle explicitly.

## Analyze progressively

Start with the smallest useful surface:

- Inspect entry points, sections, segments, imports, exports, and filtered
  strings to orient the analysis.
- Locate candidate functions by symbol/name search, address ownership, xrefs,
  callers, or callees.
- Prefer decompilation for semantics, then inspect HLIL/MLIL/LLIL or assembly
  where compiler transformations, register use, flags, or exact instruction
  bytes matter.
- Use paginated list/search tools instead of requesting unbounded catalogs.
- Use `bn_analysis_status`, `bn_analysis_update`,
  `bn_analysis_update_and_wait`, and `bn_analysis_abort` to control long-running
  Binary Ninja 6 analysis without guessing from elapsed time.
- Trace every conclusion to concrete addresses, instructions, data items, or
  cross-references. Clearly label inference when evidence is indirect.
- When source code or headers are supplied, use them as hypotheses. Verify
  types, offsets, constants, and control flow against the exact binary before
  applying declarations.

For relocatable objects or kernel modules, distinguish file-relative addresses,
section-relative offsets, linked virtual addresses, and runtime relocation.
Never silently present one address space as another.

## Apply analysis metadata carefully

Renames, comments, prototypes, calling conventions, variables, data variables,
sections, symbols, and local types modify the active analysis database. Apply
them only when requested or when the user's analysis task clearly asks for an
annotated/recovered database. Use descriptive names and record uncertainty in
comments rather than overstating a guess. Native editing tools return mutation
metadata; honor `skipAnalysisUpdate` only while deliberately batching edits,
then call `bn_analysis_update`.

Treat `patch_bytes` as destructive. Use it only when the user explicitly asks
to patch a binary. Prefer `save_to_file=false` for exploratory validation and
never overwrite the only copy of an artifact without explicit authorization.

## Report results

Lead with the finding. Include the target identity, relevant addresses or
symbol names, supporting control/data-flow evidence, important uncertainty,
and the next discriminating check when a conclusion remains open. Mention any
analysis-database mutations or file patches explicitly.

If the `mcp__binary_ninja__*` tools are absent, state that the Binary Ninja MCP
server is unavailable in the current task and use another authorized analysis
backend only if it can answer the request faithfully.
