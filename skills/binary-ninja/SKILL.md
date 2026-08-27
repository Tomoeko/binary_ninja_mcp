---
name: binary-ninja
description: Analyze native binaries, firmware images, object files, shared libraries, and Binary Ninja databases through the Binary Ninja MCP server. Use for disassembly, decompilation, HLIL/MLIL/LLIL analysis, symbols, strings, types, call graphs, cross-references, data-flow investigation, annotations, renaming, or explicitly requested binary patching with Binary Ninja.
---

# Binary Ninja

Use the `mcp__binary_ninja__*` tools for Binary Ninja analysis. Treat the MCP
server as the capability and this skill as its operating workflow.

## Open and identify the target

1. Work only on binaries the user placed in scope. Use an absolute path.
2. Call `get_binary_status` or `list_binaries` before opening a new target.
3. Call `open_binary` when the requested target is not already active, then
   retain the stable selector it returns and confirm the filename and loaded
   state with `get_binary_status(binary=<selector>)`.
4. Pass `binary=<view:N selector or absolute filename>` on every subsequent
   target-dependent tool call. This is mandatory when subagents or concurrent
   calls may share the MCP server: `select_binary` is legacy mutable state and
   is not a concurrency boundary.
5. Use `convert_number` for base, endian, character, or byte conversions; do
   not perform address-base conversions manually.

Use `list_binaries` to recover a selector for an already-open view. Prefer its
namespaced `view:N` selector or full absolute filename. Bare numeric ids are
intentionally rejected because an internal id can collide with a sorted
ordinal; `ordinal:N` is available for short-lived interactive selection only.
`select_binary` remains available for inspecting/changing the GUI's active
selection, but it does not scope later requests when multiple views are open.
Explicit `binary` arguments are the authoritative targeting mechanism.

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
- Trace every conclusion to concrete addresses, instructions, data items, or
  cross-references. Clearly label inference when evidence is indirect.
- When source code or headers are supplied, use them as hypotheses. Verify
  types, offsets, constants, and control flow against the exact binary before
  applying declarations.

For relocatable objects or kernel modules, distinguish file-relative addresses,
section-relative offsets, linked virtual addresses, and runtime relocation.
Never silently present one address space as another.

## Apply analysis metadata carefully

Renames, comments, prototypes, and local types modify the active analysis
database. Apply them only when requested or when the user's analysis task
clearly asks for an annotated/recovered database. Use descriptive names and
record uncertainty in comments rather than overstating a guess.

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
