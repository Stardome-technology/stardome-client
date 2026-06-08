# stardome-client

Linux C++ client for Stardome SWP communication with MCU targets over UART.

## Licensing

The root repository license applies to the `stardome-client` codebase itself.

Third-party dependencies referenced in `.gitmodules` and materialized under `third_party/` remain under their own respective licenses, copyright notices, and attribution terms, including public forks maintained by Stardome where applicable. See the corresponding dependency repositories and their `LICENSE`, `README`, or `NOTICE` files for provenance and redistribution details.

## Current implementation status

- Linux-only build with `gcc/g++` and `make`
- C++ CLI scaffold with command surface aligned to Python client scripts:
  - `status`, `id`, `lowmode`, `highmode`, `off`, `proof`, `attestation`, `attestation-file`, `firmware`, `timestamp`, `bootlog`, `verify`
- SWP transport wired through the `uart_sliding_window_protocol` git submodule under `third_party/`
- CBOR encode/decode migrated to the `QCBOR` git submodule under `third_party/`
- `.env` configuration support for scheme and serial defaults
- Implemented local command flows:
  - `proof`: sends proof request and writes proof artifact
  - `attestation`: sends a CBOR `FLAG_SIGN` request, writes tree + attestation artifacts, and always runs verbose verification
  - `attestation-file`: sends a raw-file `FLAG_SIGN_FILE` request, writes tree + attestation artifacts, and verifies against the equivalent one-source CBOR payload locally
  - `verify`: validates tree/attestation root binding and verifies detached XMSS signature using the configured scheme
  - `firmware`: sends firmware binary as `FLAG_STARDOME_DATA` payload
  - `timestamp`: builds 6-byte LE GPS payload and sends as `FLAG_STARDOME_DATA`
  - `bootlog get`: sends the fixed `BLOG\x01\x01` request as `FLAG_STARDOME_DATA` and appends the returned bootlog to a host log
- Strict CBOR response parsing for `status`, `id`, and `verify` (schema/type mismatches now fail fast)
- `proof` now prints a decoded proof summary and explicit `PASS`/`FAIL` validation result
- `attestation` now performs immediate verbose verification after reception, using `STARDOME_SCHEME` from `.env` unless overridden by `--scheme`
- `attestation-file --payload-file <file>` now follows the Tyvak/Python `FLAG_SIGN_FILE` path on the wire and still builds the equivalent one-source CBOR payload locally for strict verification
- Mixed third-party layout: `uart_sliding_window_protocol`, `QCBOR`, `merkle-tree`, and `stardome-cbor-schemes` are git submodules; `xmss-reference` remains a tracked snapshot under `third_party/`

## Clone

Clone with submodules so the third-party dependencies are present:

```bash
git clone --recurse-submodules https://github.com/Stardome-technology/stardome-client.git
```

If you already cloned the repo, initialize and update submodules before building:

```bash
git submodule update --init --recursive
```

Current build requirement note: the repository tracks four submodules, but the current `Makefile` only consumes and auto-refreshes `third_party/uart_sliding_window_protocol` and `third_party/qcbor` during normal builds.

## Configuration

Copy `.env.example` to `.env` and edit values:

```bash
cp .env.example .env
```

Supported variables:

- `STARDOME_SCHEME` (default: `v1.0.0_0`)
- `STARDOME_PORT` (default: `/dev/ttyUSB0`)
- `STARDOME_BAUD` (default: `115200`)

CLI flags override `.env` values.

## Build

```bash
make clean && make -j4
```

Build note: each `make` build refreshes `third_party/uart_sliding_window_protocol` and `third_party/qcbor` to the configured remote branch before compiling.

`third_party/merkle-tree` and `third_party/stardome-cbor-schemes` are tracked as submodules for dependency layout and provenance, but they are not yet part of the current compile path.

Binary output:

- `bin/stardome-client`

## Usage

```bash
./bin/stardome-client --port /dev/ttyUSB0 --baud 115200 status
```

Important: global options (`--port`, `--baud`, `--scheme`, `--env`, `--verbose`) must appear before the command name.

Command-specific help:

```bash
./bin/stardome-client proof --help
./bin/stardome-client attestation --help
./bin/stardome-client attestation-file --help
./bin/stardome-client off --help
./bin/stardome-client lowmode --help
./bin/stardome-client highmode --help
./bin/stardome-client bootlog --help
```

Status and identity commands:

```bash
./bin/stardome-client --port /dev/ttyUSB0 status
./bin/stardome-client --port /dev/ttyUSB0 id get
./bin/stardome-client --port /dev/ttyUSB0 id set --hex 001122AABB
./bin/stardome-client --port /dev/ttyUSB0 lowmode
./bin/stardome-client --port /dev/ttyUSB0 highmode
```

Status response semantics:

- `status` expects `FLAG_STARDOME_STATUS_DATA` with a CBOR uint payload
- value mapping: `1=IDLE`, `2=BUSY`, `3=BOOTING`, `4=ERROR`

Identity response semantics:

- `id get/set` expects `FLAG_STARDOME_ID_DATA` with the ID response scheme payload

`id` notes:

- `id` with no subcommand defaults to `get`.
- `id set` accepts binary bytes as a CLI hex argument (`--hex`, optional `0x` prefix, spaces ignored).
- Set payload must be 1..1024 bytes.

Examples:

```bash
./bin/stardome-client --port /dev/ttyUSB0 proof --tree-file stardome_tree.bin --leaf-index 0 --out-proof stardome_proof.bin
./bin/stardome-client --port /dev/ttyUSB0 attestation --out-tree stardome_tree.bin --out-attestation stardome_attestation.bin
./bin/stardome-client verify --tree stardome_tree.bin --attestation stardome_attestation.bin
./bin/stardome-client --port /dev/ttyUSB0 off
./bin/stardome-client --port /dev/ttyUSB0 firmware --file app.bin
./bin/stardome-client --port /dev/ttyUSB0 timestamp --iso-utc 2026-02-20T12:00:00Z
./bin/stardome-client --port /dev/ttyUSB0 bootlog get
```

Timestamp precedence notes:

- Default path: if `--gps-week`/`--tow-seconds` are not provided, the command uses UTC input (`--iso-utc` if set, otherwise current host UTC) and converts to GPS week/TOW.
- Override path: if both `--gps-week` and `--tow-seconds` are provided, those values are sent directly and UTC conversion is bypassed.
- `FLAG_STARDOME_DATA` is a generic ingress path. Current Pathfinder dispatcher classifies payloads as firmware/timestamp/bootlog/fpga-mock/unknown.
- `bootlog get` sends the reserved six-byte discriminator `424c4f470101` (`BLOG\x01\x01`) and expects bootlog bytes back on `FLAG_STARDOME_DATA` or an error on `FLAG_STARDOME_DATA_ERROR`.
- By default, `bootlog get` appends to `bootlogs/<device-key>.log`, using `installation_id`, then `host_id`, then port plus collection timestamp as the device key. Use `--out <path>` to select a specific append file, `--dir <dir>` to select the default log directory, `--print` to also print the returned bytes, or `--no-append` to print without writing.
- `FLAG_STARDOME_DATA_ERROR` is reserved for ingress/classification/runtime faults (for example unsupported payload type `0x0B` or bootlog I/O failure `0x0C`).
- Internal parse/apply failures after successful transfer are log-only on firmware and may not emit an explicit error frame.
- Legacy OTA-only firmware may still return `FLAG_STARDOME_DATA_ERROR code=0x04` (descriptor invalid for OTA path).

`off` note: some MCU builds defer off-state and may not send an explicit response frame. In that case, the client reports success after the wait window (default `1200` ms, configurable via `off --wait-ms N`).

Payload workflows:

```bash
# Generate attestation payload from an input file 
./bin/stardome-client attestation --payload-file ./payloads/payload_100KB.txt --generate-payload my_payload.cbor

# Generate default attestation payload without sending
./bin/stardome-client attestation --out-payload-cbor attestation_payload.cbor

# Send prebuilt attestation payload
./bin/stardome-client --port /dev/ttyUSB0 attestation --payload-cbor my_payload.cbor --out-tree stardome_tree.bin --out-attestation stardome_attestation.bin

# Build a one-source CBOR attestation request from a raw file and send FLAG_SIGN
./bin/stardome-client --port /dev/ttyUSB0 attestation --payload-file ./payloads/payload_100KB.txt --out-tree stardome_tree.bin --out-attestation stardome_attestation.bin

# Raw-file attestation request (FLAG_SIGN_FILE)
./bin/stardome-client --port /dev/ttyUSB0 attestation-file --payload-file ./payloads/payload_100KB.txt --out-tree stardome_tree.bin --out-attestation stardome_attestation.bin

# Generate proof request payload without sending
./bin/stardome-client proof --tree-file stardome_tree.bin --leaf-index 0 --out-payload-cbor proof_payload.cbor

# Send prebuilt proof payload
./bin/stardome-client --port /dev/ttyUSB0 proof --payload-cbor proof_payload.cbor --out-proof stardome_proof.bin
```

## Third-party source policy (current phase)

Third-party dependencies are currently managed as a mix of git submodules and copied snapshots. To minimize duplication and make updates predictable, the canonical source-of-truth for dependency and provenance information is this `README.md` section.

Current dependency layout: see .gitmodules

How to initialize after cloning (recommended on WSL):

```bash
# clone with submodules
git clone --recurse-submodules https://github.com/Stardome-technology/stardome-client.git

# or, if you already cloned:
git submodule update --init --recursive

# verify submodule status
git submodule status --recursive
```

Client-owned XMSS wrapper and host utility code now lives under `src/xmss/platform`. The remaining copied trees are intentionally small snapshots required for build/runtime; we aim to convert more of these to submodules when practical.

## Next steps

- Replace local tree decode and leaf-hash verification in `src/verify/stardome_attestation_verify.cpp` with `third_party/merkle-tree` secure tree decode/verification helpers
- Deepen frame-type-aware response demux (distinguish normal data vs explicit Stardome error frames)
- Add hardware-backed parity runs against `stardome-local-python-client` command outputs
- Add wire-compatibility and integration tests

## Updating Submodule Gitlinks

When upstream for a submodule has advanced and you want the parent repo to point at the latest remote branch tip, follow these safe steps.
If `git submodule update` fails with errors like "did not contain <commit>" or
"upload-pack: not our ref", the superproject references a commit that isn't present
on the submodule remote. Recover by updating the submodule to a reachable branch and
recording the new gitlink (recommended)

1) Inspect current submodule status:

```
git submodule status --recursive
```

2) Fetch remotes for all submodules:

```
git submodule foreach --recursive 'git fetch --all --prune'
```

3) Update a single submodule to its remote branch tip (example for `third_party/qcbor`):

```
git -C third_party/qcbor fetch origin
# checkout origin/<branch> as local branch
git -C third_party/qcbor checkout -B stardome-stripped origin/stardome-stripped
# record new gitlink in parent
git add third_party/qcbor
git commit -m "Update QCBOR submodule to origin/stardome-stripped"
```

5) Notes and safety:
- Prefer creating a branch/PR in the submodule and merging upstream before updating the parent; that preserves reviewability.
- `git submodule update --remote <path>` can be used to update a submodule to the tip of the branch configured in `.gitmodules` (if the submodule is configured to track a branch).
- Always run a full build after updating submodules to verify compatibility.

