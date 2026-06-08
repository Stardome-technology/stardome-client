# Lessons

- Keep SWP wire-level implementation in C and isolate it behind a small bridge API.
- Read scheme defaults from `.env` once and pass through command handlers.
- Start with single-port serial mode for Linux baseline before device-specific tuning branches.
- When vendoring for an MVP, immediately prune to source/header-only assets and drop vendor tests/docs to keep maintenance surface minimal.
- For parity with Python verification behavior, treat XMSS signatures as detached (`sig || message`) when calling the reference verifier and keep explicit failure-reason propagation for CLI diagnostics.
- Prefer frame-flag-aware demux over payload-length heuristics by carrying metadata (`flags`, `encoding`, frame indices) from SWP decode up to command handlers.
- Multi-response commands should assert expected frame classes in order (e.g., tree then attestation) to avoid silently accepting out-of-order or wrong-type payloads.
- When protocol semantics change (like OFF payload/ACK rules), update firmware handling, Python tooling, C++ CLI routing, and protocol docs in the same pass to avoid temporary host/device contract drift.
