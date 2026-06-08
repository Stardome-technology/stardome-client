# Stardome Client TODO

## Current protocol contract (latest)

- Identity request flag: `FLAG_STARDOME_ID` (`0x40`)
- Identity success response flag: `FLAG_STARDOME_ID_DATA` (`0xB0`)
- Identity error response flag: `FLAG_STARDOME_ID_ERROR` (`0xCC`)
- Status request flag: `FLAG_STARDOME_STATUS` (`0x10`)
- Status success response flag: `FLAG_STARDOME_STATUS_DATA` (`0x90`), payload is CBOR uint (`1=IDLE,2=BUSY,3=BOOTING,4=ERROR`)
- Bootlog request path: `bootlog get` sends `FLAG_STARDOME_DATA` payload `BLOG\x01\x01`; success response is `FLAG_STARDOME_DATA` bootlog bytes, error response is `FLAG_STARDOME_DATA_ERROR`.
- Board-status request/response path is removed (hard-cut)

Historical entries below are retained as implementation log and may reference superseded names.

## Supersession notes (2026-03-03)

- Any historical mention of `host-id` command naming maps to current `id` command naming.
- Any historical mention of `board-status` request/response is obsolete (hard-cut removed).
- Any historical mention of `status` returning identity-map fields (`fw/host_id/installation_id/response_version`) is obsolete.
- Current split is authoritative:
	- `status` → `FLAG_STARDOME_STATUS_DATA` with CBOR uint status code
	- `id` → `FLAG_STARDOME_ID_DATA` with `stardome_host_id_response` map payload

## Plan (current iteration)

- [x] Hard-cut protocol rename `FLAG_STARDOME_HOST_ID` -> `FLAG_STARDOME_ID` across protocol headers and clients
- [x] Remove board-status command path from C++ client and protocol docs
- [x] Refactor Pathfinder serial dispatcher to handle `FLAG_STARDOME_ID` and drop board-status branch
- [x] Align host-id response serializer in Pathfinder to scheme keys `1=>fw,2=>host_id,?3=>installation_id,4=>response_version`
- [x] Update Python client constants/scripts for ID flags and deprecate board-status script
- [x] Update C++/Python/protocol README command references (`id`, status-only)
 - [x] Add Pathfinder `src/cbor_schemes` submodule declaration for remote schema repository
- [x] Clean rebuild and CLI smoke checks

- [x] Align `status` decoder to firmware CDDL payload shape (1=>fw, 2=>host_id, ?3=>installation_id, 4=>response_version)
- [x] Align `host-id` decoder to same firmware CDDL payload shape with documented legacy binary fallback
- [x] Align Python `send_status_request_stardome.py` decoder to firmware CDDL payload shape only
- [x] Align Python `send_host_id_stardome.py` decoder to firmware CDDL payload shape with legacy binary fallback
- [x] Rebuild C++ client and run diagnostics checks on modified files

- [x] Align C++ `host-id get` output schema with Python status/host-id output labels
- [x] Add C++ `host-id` legacy raw-payload fallback decode path for firmware compatibility
- [x] Normalize C++ `board-status` hex formatting to fixed-width parity (`0x01`)
- [x] Add C++ ↔ Python command mapping notes in docs
- [x] Rebuild and run CLI smoke checks for alignment changes

- [x] Add C++ `host-id` subcommands (`get`/`set`) with file-based set payload
- [x] Extend shared command transport helper for payload-bearing request/response flows
- [x] Update C++ CLI usage/docs for host-id set support
- [x] Refactor Python host-id sender to normalize set inputs through raw-bytes path with length validation
- [x] Update Python usage docs/quick commands to prefer file-based raw bytes host-id set
- [x] Rebuild and run command parsing smoke checks

- [x] Align OFF protocol contract across firmware + clients (ignore request payload, empty ACK, generic OFF error)
- [x] Refactor Pathfinder OFF path to import XMSS safe shutdown before halt
- [x] Update Python OFF sender to transmit empty payload
- [x] Add C++ `off` command and CLI wiring in stardome-client
- [x] Update protocol/client documentation for OFF command semantics
- [x] Define cleanup policy for vendored dependencies (conservative pass)
- [x] Remove vendored test/demo/docs and ignore files not needed for build/runtime
- [x] Update third-party provenance after pruning
- [x] Implement `status` command response parity (decode and print expected fields)
- [x] Implement `host-id` command response parity (decode and print expected fields)
- [x] Add C++ `bootlog get` command over `FLAG_STARDOME_DATA` with host-side append/print support
- [x] Rebuild recloned/integrated C++ client on WSL after carrying forward bootlog changes
- [ ] Hardware-test `bootlog get` against Pathfinder and confirm bootlog response/display/append behavior
- [x] Rebuild and run CLI smoke checks

## Review (concise)

- Hard-cut protocol split is complete and authoritative:
	- `id` flow: `FLAG_STARDOME_ID` (`0x40`) request, `FLAG_STARDOME_ID_DATA` (`0xB0`) success, `FLAG_STARDOME_ID_ERROR` (`0xCC`) error.
	- `status` flow: `FLAG_STARDOME_STATUS` (`0x10`) request, `FLAG_STARDOME_STATUS_DATA` (`0x90`) success with CBOR uint status payload.
- `board-status` is fully removed from active firmware/C++/Python command paths (deprecated shim remains only for migration messaging in Python).
- Firmware serializer/dispatch and both clients are aligned to current contract (`id` map payload vs `status` uint payload).
- Protocol and client docs are updated for `id` naming and board-status removal.
 - Pathfinder schema linkage is configured via submodule at `src/cbor_schemes`.
- Latest C++ verification in this iteration passed on WSL after recloning/integrating the bootlog work; CLI command surface is `status | id | lowmode | highmode | off | proof | attestation | attestation-file | firmware | timestamp | bootlog | verify`.
- `bootlog get` is implemented but still needs hardware verification against Pathfinder before the host-side bootlog request workflow is considered fully proven.

Historical review detail has been intentionally compacted; full chronology remains available in git history.
