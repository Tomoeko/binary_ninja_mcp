# Binary Ninja MCP

This repository contains a Binary Ninja plugin, MCP server, and bridge that enables seamless integration of Binary Ninja's capabilities with your favorite LLM client.

![Binary Ninja MCP Logo](images/logo-small.png)

## Features

- Seamless, real-time integration between Binary Ninja and MCP clients
- Enhanced reverse engineering workflow with AI assistance
- Support for every MCP client (Cline, Claude desktop, Roo Code, etc.)
- Target multiple open binaries deterministically with explicit selectors
- Headless compatibility with Binary Ninja 6.0.10601's complete 75-tool
  native `bn_*` MCP vocabulary

## Examples

### Solving a CTF Challenge

Check out [this demo video on YouTube](https://www.youtube.com/watch?v=0ffMHH39L_M) that uses the extension to solve a CTF challenge.

## Components

This repository contains two separate components:

1. A Binary Ninja plugin that provides an MCP server that exposes Binary Ninja's capabilities through HTTP endpoints. This can be used with any client that implements the MCP protocol.
2. A separate MCP bridge component that connects your favorite MCP client to the Binary Ninja MCP server.

## Prerequisites

- [Binary Ninja](https://binary.ninja/)
- Python 3.12+
- MCP client (those with auto-setup support are listed below)

## Installation

### MCP Client

Please install the MCP client before you install Binary Ninja MCP so that the MCP clients can be auto-setup. We currently support auto-setup for these MCP clients:

    1. Cline (recommended)
    2. Roo Code
    3. Claude Desktop (recommended)
    4. Cursor
    5. Windsurf
    6. Claude Code
    7. LM Studio

### Extension Installation

After the MCP client is installed, you can install the MCP server using the Binary Ninja Plugin Manager or manually. Both methods support auto-setup of MCP clients.

If your MCP client is not set, you should install it first then try to reinstall the extension.

#### Binary Ninja Plugin Manager

You may install the extension through Binary Ninja's Plugin Manager (`Plugins > Manage Plugins`).

![Plugin Manager](images/plugin-manager-listing.png)

#### Manual Install

To manually install the extension, this repository can be copied into the [Binary Ninja plugins folder](https://docs.binary.ninja/guide/plugins.html).

### [Optional] Manual Setup of the MCP Client

*You do NOT need to set this up manually if you use a supported MCP client and follow the installation steps before.*

You can also manage MCP client entries from the command line:

```bash
python scripts/mcp_client_installer.py --install    # auto setup supported MCP clients
python scripts/mcp_client_installer.py --uninstall  # remove entries and delete `.mcp_auto_setup_done`
python scripts/mcp_client_installer.py --config     # print a generic JSON config snippet
```

For Codex, `--install` installs both the bundled Binary Ninja analysis skill at
`${CODEX_HOME:-~/.codex}/skills/binary-ninja` and a persistent headless
`binary_ninja` MCP server entry. The installer losslessly merges the entry so
existing environment, enablement, tool-filter, and approval settings survive a
reinstall. Absolute paths are recorded for the Python interpreter, launcher,
and bridge environment, so the server does not depend on the launching
application's working directory. This workflow never launches or contacts the
Binary Ninja GUI. `--uninstall` removes only the files and server entry managed
by this repository. Start a new Codex task after installation so the MCP tool
catalog and skill catalog are refreshed.

Codex starts one stdio MCP client per task or subagent. Those clients reuse one
authenticated, OS-assigned loopback Binary Ninja host keyed by its exact
runtime and repository source fingerprint; the endpoint and credentials remain
private to the current user. The host receives isolated writable Binary Ninja
user state so concurrent native-plugin initialization cannot corrupt the real
Plugin Manager status file. When agents share this headless host, pass the
exact type-qualified `binaryView` candidate handle returned by the native
lifecycle tools as `binary=` on every native active-view call. Extended legacy
tools use the stable `view:N` selector or an absolute filename. Do not rely on
the mutable legacy current-view state set by `select_binary`. Bare numeric
selectors are rejected because internal ids and sorted ordinals can collide.
With multiple binaries open, an unscoped target-dependent request fails closed
rather than using another agent's view.

#### Using npm package (Recommended)

The recommended way to set up the MCP client is using the official npm package:

```bash
npx -y binary-ninja-mcp
```

For MCP clients, use this configuration:

```json
{
  "mcpServers": {
    "binary-ninja-mcp": {
      "command": "npx",
      "args": ["-y", "binary-ninja-mcp", "--host", "localhost", "--port", "9009"]
    }
  }
}
```

Or if installed globally:

```json
{
  "mcpServers": {
    "binary-ninja-mcp": {
      "command": "binary-ninja-mcp",
      "args": ["--host", "localhost", "--port", "9009"]
    }
  }
}
```

#### Using Python Bridge (Legacy)

For other MCP clients, use the Python bridge directly:

```json
{
    "mcpServers": {
        "binary_ninja_mcp": {
            "command": "/ABSOLUTE/PATH/TO/Binary Ninja/plugins/repositories/community/plugins/fosdickio_binary_ninja_mcp/.venv/bin/python",
            "args": [
                "/ABSOLUTE/PATH/TO/Binary Ninja/plugins/repositories/community/plugins/fosdickio_binary_ninja_mcp/bridge/binja_mcp_bridge.py"
            ]
        }
    }
}
```

Note: Replace `/ABSOLUTE/PATH/TO` with the actual absolute path to your project directory. The virtual environment's Python interpreter must be used to access the installed dependencies.

### Headless Binary Ninja for Codex

The headless launcher starts Binary Ninja's Python API, the local HTTP service,
and the MCP stdio bridge as one command. It never launches, attaches to, or
automates the Binary Ninja GUI.

#### Binary Ninja 6 native MCP model

Binary Ninja 6.0.10601 defines 75 native MCP tools for file/view management,
projects, analysis control, program structure, memory reads, function and IL
inspection, cross-references, symbols, variables, prototypes, calling
conventions, types, data variables, comments, and section editing. This
repository exposes those exact `bn_*` names and native-style input schemas on
its existing headless Codex server, alongside the extended legacy tools.

Vector 35 ships its standalone `binaryninja_mcp` stdio executable only with
Commercial and Ultimate editions on macOS/Linux; Personal 6.0.10601 contains
the GUI MCP implementation but not that executable. The compatibility layer
therefore uses the installed 6.0 Python API inside the repository's isolated
headless host. It never starts or connects to the Binary Ninja GUI.

Every native file or database opened by the compatibility layer has an
`openItem` handle of the form `open:view:N`. `bn_binary_view_list` and
`bn_open_item_open` return stable, type-qualified `binaryView` candidate
handles of the form `candidate:view:N:<encoded-view-type>`. Pass the returned
candidate handle verbatim as `binary=` on native active-view tools; it selects
the exact Raw, Mach-O, ELF, PE, or other view type in the headless process.

The legacy `view:N` selector identifies the open item and its current analyzed
view. It is not a native, type-qualified `binaryView` candidate handle.
`bn_binary_view_set_active` changes the headless current analyzed view and may
create the requested view type, but no GUI selection exists. Calls without an
explicit selector fail closed when more than one item is resident. The nine
handle-based lifecycle tools remain unscoped, matching the native model.

First verify the same Python runtime Binary Ninja uses:

```bash
PYTHONPATH="/Applications/Binary Ninja.app/Contents/Resources/python" \
python3.13 -c "import binaryninja"
```

Then validate that the native architecture and file-format plugins also initialize:

```bash
python3.13 scripts/run_headless_mcp.py --check
```

The import check alone is not sufficient: `--check` intentionally fails if Binary
Ninja exposes only `Raw`/`Mapped` views or no architectures, because that runtime
would open files without producing useful functions or decompilation.

The launcher needs a Python environment containing `mcp` and `requests` for the
stdio bridge. It automatically detects this repository's `.venv` and the virtual
environment created by the installed Binary Ninja plugin. You can also select one:

```bash
export BINJA_MCP_BRIDGE_PYTHON="/absolute/path/to/.venv/bin/python"
```

The installer performs the following Codex configuration automatically. For a
manual installation, add the launcher to Codex's MCP configuration:

```toml
[mcp_servers.binary_ninja]
command = "python3.13"
args = ["/ABSOLUTE/PATH/TO/binary_ninja_mcp/scripts/run_headless_mcp.py"]
startup_timeout_sec = 45
tool_timeout_sec = 1800
```

The bridge uses a five-second loopback connection timeout and a finite
29-minute response-read timeout. Binary Ninja analysis requests are serialized
for database safety and can legitimately queue behind decompilation on a large
target; the longer read budget prevents the former five-second queue failure
while still bounding a wedged worker. Override these independently with
`BINJA_MCP_HTTP_CONNECT_TIMEOUT_SEC` and `BINJA_MCP_HTTP_READ_TIMEOUT_SEC`.
Codex is configured with a minimum 30-minute tool-response budget. Reinstalling
raises shorter startup/tool budgets to these minimums, preserves larger
user-defined budgets, and does not change the user's tool approval policy.

After Codex restarts, use `bn_open_item_list`/`bn_open_item_open` for the native
Binary Ninja 6 workflow, or use the extended `open_binary` MCP tool with an
absolute path when you need explicit load settings. Opening establishes the
headless current analyzed view promptly, then runs conservative `basic`
analysis in the background so large flat firmware images do not block the MCP
transport. `get_binary_status` reports the active analysis state, function
count, platform, and mapped range. An adjacent JSON file with a `base` or
`image_base` field is applied automatically; `platform`, `image_base`, and
`analysis_mode` can also be passed explicitly. Use `analysis_mode="full"` only
when the additional analysis cost is intentional.

Tool responses include readable plain text alongside structured JSON. The text
view presents code and nested results without JSON escaping; clients should
consume `structuredContent` for the original machine-readable values. This
applies to both native and legacy tools, including empty lists and tool errors.

Decompilation and IL requests re-enable the selected function if background
analysis marks it skipped while a request is waiting. They do not wait for
analysis of the entire binary. Pending-analysis warnings remain visible when
the returned text may still change.

For a repeatable cold/repeated decompilation check, run
`.venv/bin/python3 tests/smoke_function_decompile.py --help`, then supply a binary
and its function addresses. The smoke test verifies both response forms,
closes the binary, and removes its temporary host files.

Headless sessions retain at most eight native analysis views by default, which
allows a full four-agent Codex group to keep two explicitly targeted binaries
per agent. Exact
path, symlink, and hard-link aliases reuse one view when their immutable load
settings match; conflicting analysis mode, platform, image base, or a changed
on-disk file is rejected instead of silently reusing the wrong analysis. The
least-recently-used clean view is disposed before a ninth target opens, and the
versioned recovery manifest is replaced atomically so an evicted target is not
resurrected after a host restart. Set `BINJA_MCP_MAX_OPEN_BINARIES` to another
positive integer when a deliberate comparison needs a different bound. The
resident-memory ceiling described below remains authoritative regardless of
this view-count limit.

The host also enforces a 16 GiB resident-memory ceiling. If native analysis
crosses it, all managed views are aborted and disposed, the empty inventory is
persisted, and the process is recycled so allocator high-water memory is
actually returned to the operating system. Override the ceiling in MiB with
`BINJA_MCP_MAX_RSS_MB`. The `close_binary` tool releases a selected view sooner;
modified views require its explicit `discard=true` option. String pagination
and filtering retain only the requested result page rather than constructing a
Python dictionary for every discovered string on every request.

A startup target can instead be supplied by appending `--binary`, followed by
its path, to `args`. The launcher supervises both children and tears down the
bridge if the Binary Ninja HTTP host exits, preventing a stale MCP process that
accepts calls while no analysis service is listening. Leave `enabled_tools`
unset to expose the complete tool set, or retain a narrower user-defined list.

## Usage

For Codex/headless use, install the configuration, start a new Codex task, and
open the target with `bn_open_item_open` or `open_binary`. All analysis runs in
the isolated Python-API host; this workflow never launches the Binary Ninja
GUI.

You may now start prompting LLMs about the currently open binary (or binaries). Example prompts:

### CTF Challenges

```txt
You're the best CTF player in the world. Please solve this reversing CTF challenge in the <folder_name> folder using Binary Ninja. Rename ALL the function and the variables during your analyzation process (except for main function) so I can better read the code. Write a python solve script if you need. Also, if you need to create struct or anything, please go ahead. Reverse the code like a human reverser so that I can read the decompiled code that analyzed by you.
```

### Malware Analysis

```txt
Your task is to analyze an unknown file which is currently open in Binary Ninja. You can use the existing MCP server called "binary_ninja_mcp" to interact with the Binary Ninja instance and retrieve information, using the tools made available by this server. In general use the following strategy:

- Start from the entry point of the code
- If this function call others, make sure to follow through the calls and analyze these functions as well to understand their context
- If more details are necessary, disassemble or decompile the function and add comments with your findings
- Inspect the decompilation and add comments with your findings to important areas of code
- Add a comment to each function with a brief summary of what it does
- Rename variables and function parameters to more sensible names
- Change the variable and argument types if necessary (especially pointer and array types)
- Change function names to be more descriptive, using mcp_ as prefix.
- NEVER convert number bases yourself. Use the convert_number MCP tool if needed!
- When you finish your analysis, report how long the analysis took
- At the end, create a report with your findings.
- Based only on these findings, make an assessment on whether the file is malicious or not.
```

## Supported Capabilities

The following table lists the available MCP functions for use:

| Function                                                             | Description                                                                                                  |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `decompile_function`                                                 | Decompile a specific function by name and return HLIL-like code with addresses.                              |
| `get_il(name_or_address, view, ssa)`                                 | Get IL for a function in `hlil`, `mlil`, or `llil` (SSA supported for MLIL/LLIL).                            |
| `define_types`                                                       | Add type definitions from a C string type definition.                                                        |
| `delete_comment`                                                     | Delete the comment at a specific address.                                                                    |
| `delete_function_comment`                                            | Delete the comment for a function.                                                                           |
| `declare_c_type(c_declaration)`                                      | Create/update a local type from a single C declaration.                                                      |
| `format_value(address, text, size)`                                  | Convert a value and annotate it at an address in BN (adds a comment).                                        |
| `function_at`                                                        | Retrieve the name of the function the address belongs to.                                                    |
| `fetch_disassembly`                                              | Get the assembly representation of a function by name or address.                                            |
| `get_entry_points()`                                                 | List entry point(s) of the loaded binary.                                                                    |
| `get_binary_status`                                                  | Get the current status of the loaded binary.                                                                 |
| `open_binary(filepath)`                                              | Open and select a local binary in a GUI-free/headless session.                                               |
| `get_comment`                                                        | Get the comment at a specific address.                                                                       |
| `get_function_comment`                                               | Get the comment for a function.                                                                              |
| `get_user_defined_type`                                              | Retrieve definition of a user-defined type (struct, enumeration, typedef, union).                            |
| `get_xrefs_to(address)`                                              | Get all cross references (code and data) to an address.                                                      |
| `get_data_decl(name_or_address, length)`                             | Return a C-like declaration and a hexdump for a data symbol or address.                                      |
| `hexdump_address(address, length)`                                   | Text hexdump at address. `length < 0` reads exact defined size if available.                                 |
| `hexdump_data(name_or_address, length)`                              | Hexdump by data symbol name or address. `length < 0` reads exact defined size if available.                  |
| `get_xrefs_to_enum(enum_name)`                                       | Get usages related to an enum (matches member constants in code).                                            |
| `get_xrefs_to_field(struct_name, field_name)`                        | Get all cross references to a named struct field.                                                            |
| `get_xrefs_to_struct(struct_name)`                                   | Get xrefs/usages related to a struct (members, globals, code refs).                                          |
| `get_xrefs_to_type(type_name)`                                       | Get xrefs/usages related to a struct/type (globals, refs, HLIL matches).                                     |
| `get_xrefs_to_union(union_name)`                                     | Get xrefs/usages related to a union (members, globals, code refs).                                           |
| `get_stack_frame_vars(function_identifier)`                          | Get stack frame variable information for a function (names, offsets, sizes, types).                           |
| `get_type_info(type_name)`                                           | Resolve a type and return declaration, kind, and members.                                                    |
| `get_callers(identifiers)`                                           | List callers plus call sites for one or more function identifiers.                                           |
| `get_callees(identifiers)`                                           | List callees plus call sites for one or more function identifiers.                                           |
| `make_function_at(address, platform)`                                | Create a function at an address. `platform` optional; use `default` to pick the BinaryView/platform default. |
| `list_platforms()`                                                   | List all available platform names.                                                                           |
| `list_binaries()`                                                    | List managed/open binaries with ids and active flag.                                                         |
| `select_binary(view)`                                                | Set the legacy headless current analyzed view by `view:N`, `ordinal:N`, full path, or unambiguous basename.  |
| `list_all_strings()`                                                 | List all strings (no pagination; aggregates all pages).                                                      |
| `list_classes`                                                       | List all namespace/class names in the program.                                                               |
| `list_data_items`                                                    | List defined data labels and their values.                                                                   |
| `list_exports`                                                       | List exported functions/symbols.                                                                             |
| `list_imports`                                                       | List imported symbols in the program.                                                                        |
| `list_local_types(offset, count)`                                    | List local Types in the current database (name/kind/decl).                                                   |
| `list_methods`                                                       | List all function names in the program.                                                                      |
| `list_namespaces`                                                    | List all non-global namespaces in the program.                                                               |
| `list_segments`                                                      | List all memory segments in the program.                                                                     |
| `list_strings(offset, count)`                                        | List all strings in the database (paginated).                                                                |
| `list_strings_filter(offset, count, filter)`                         | List matching strings (paginated, filtered by substring).                                                    |
| `rename_data`                                                        | Rename a data label at the specified address.                                                                |
| `rename_function`                                                    | Rename a function by its current name to a new user-defined name.                                            |
| `rename_single_variable`                                             | Rename a single local variable inside a function.                                                            |
| `rename_multi_variables`                                             | Batch rename multiple local variables in a function (mapping or pairs).                                      |
| `set_local_variable_type(function_address, variable_name, new_type)` | Set a local variable's type.                                                                                 |
| `retype_variable`                                                    | Retype variable inside a given function.                                                                     |
| `search_functions_by_name`                                           | Search for functions whose name contains the given substring.                                                |
| `search_types(query, offset, count)`                                 | Search local Types by substring (name/decl).                                                                 |
| `set_comment`                                                        | Set a comment at a specific address.                                                                         |
| `set_function_comment`                                               | Set a comment for a function.                                                                                |
| `set_function_prototype(name_or_address, prototype)`                 | Set a function's prototype by name or address.                                                               |
| `patch_bytes(address, data, save_to_file)`                           | Patch raw bytes at an address (byte-level, not assembly). Can patch entire instructions by providing their bytecode. Address: hex (e.g., "0x401000") or decimal. Data: hex string (e.g., "90 90"). `save_to_file` (default True) saves to disk and re-signs on macOS. |

These are the list of HTTP endpoints that can be called:

- `/allStrings`: All strings in one response.
- `/formatValue?address=<addr>&text=<value>&size=<n>`: Convert and set a comment at an address.
- `/getXrefsTo?address=<addr>`: Xrefs to address (code+data).
- `/getDataDecl?name=<symbol>|address=<addr>&length=<n>`: JSON with declaration-style string and a hexdump for a data symbol or address. Keys: `address`, `name`, `size`, `type`, `decl`, `hexdump`. `length < 0` reads exact defined size if available.
- `/hexdump?address=<addr>&length=<n>`: Text hexdump aligned at address; `length < 0` reads exact defined size if available.
- `/hexdumpByName?name=<symbol>&length=<n>`: Text hexdump by symbol name. Recognizes BN auto-labels like `data_<hex>`, `byte_<hex>`, `word_<hex>`, `dword_<hex>`, `qword_<hex>`, `off_<hex>`, `unk_<hex>`, and plain hex addresses.
- `/makeFunctionAt?address=<addr>&platform=<name|default>`: Create a function at an address (idempotent if already exists). `platform=default` uses the BinaryView/platform default.
- `/platforms`: List all available platform names.
- `/binaries` or `/views`: List managed/open binaries with ids and active flag.
- `/selectBinary?view=<id|filename>`: Select active binary for subsequent operations.
- `/data?offset=<n>&limit=<m>&length=<n>`: Defined data items with previews. `length` controls bytes read per item (capped at defined size). Default behavior reads exact defined size when available; `length=-1` forces exact-size.
- `/getXrefsToEnum?name=<enum>`: Enum usages by matching member constants.
- `/getXrefsToField?struct=<name>&field=<name>`: Xrefs to struct field.
- `/getXrefsToType?name=<type>`: Xrefs/usages related to a struct/type name.
- `/getTypeInfo?name=<type>`: Resolve a type and return declaration and details.
- `/getXrefsToUnion?name=<union>`: Union xrefs/usages (members, globals, refs).
- `/getStackFrameVars?name=<function>|address=<addr>`: Get stack frame variable information for a function.
- `/getCallers?identifiers=<name|addr>[,...]`: Return caller summaries (functions, call sites, HLIL/IL snippets) for one or more identifiers. Accepts `identifiers`, `identifier`, `names`, or `addresses` query params.
- `/getCallees?identifiers=<name|addr>[,...]`: Return callee summaries with the same schema as `/getCallers`, detailing every outgoing call target per request identifier.
- `/localTypes?offset=<n>&limit=<m>`: List local types.
- `/strings?offset=<n>&limit=<m>`: Paginated strings.
- `/strings/filter?offset=<n>&limit=<m>&filter=<substr>`: Filtered strings.
- `/searchTypes?query=<substr>&offset=<n>&limit=<m>`: Search local types by substring.
- `/patch` or `/patchBytes?address=<addr>&data=<hex>&save_to_file=<bool>`: Patch raw bytes at an address (byte-level, not assembly). Can patch entire instructions by providing their bytecode. Address: hex (e.g., "0x401000") or decimal. Data: hex string (e.g., "90 90"). `save_to_file` (default True) saves to disk and re-signs on macOS.
- `/renameVariables`: Batch rename locals in a function. Parameters:
  - Function: one of `functionAddress`, `address`, `function`, `functionName`, or `name`.
  - Provide renames via one of:
    - `renames`: JSON array of `{old, new}` objects
    - `mapping`: JSON object of `old->new`
    - `pairs`: compact string `old1:new1,old2:new2`
          Returns per-item results plus totals. Order is respected; later pairs can refer to earlier new names.

## Development

### Code Quality

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting. Configuration is in `ruff.toml`.

#### Running Ruff Manually

Check for issues:
```bash
ruff check .
```

Auto-fix issues:
```bash
ruff check --fix .
```

Check formatting issues:
```bash
ruff format --check .
```

Format code:
```bash
ruff format .
```

#### GitHub Actions

A GitHub Action workflow (`.github/workflows/lint-format.yml`) automatically runs Ruff on:

- Every push to the `main` branch
- Every pull request targeting the `main` branch

The workflow will fail if there are linting errors or formatting issues, ensuring code quality in CI.

## Contributing

Contributions are welcome. Please feel free to submit a pull request.
