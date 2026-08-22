# HiddenCover Artifact

This repository contains the research prototype and reproducibility package for
HiddenCover, a privacy-preserving anonymous-credential revocation mechanism.
The prototype is implemented in Rust over BLS12-381. It combines BBS
multi-message signatures, Pedersen commitments, and a Groth--Kohlweiss-style
one-out-of-many proof instantiated over a common scalar field.

This is research software. It has not undergone a production security audit and
must not be used to protect real credentials.

## Artifact contents

- `src/tree.rs`: complete binary tree, leaf allocation, and Complete Subtree cover.
- `src/credential.rs`: per-path BBS signatures and hidden signature-possession proof.
- `src/oom.rs`: one-out-of-many proof over the shared scalar field.
- `src/protocol.rs`: `Setup`, `Issue`, `Revoke`, `Show`, `Verify`, and signed state.
- `src/lib.rs`: correctness and adversarial tests, including revoked credentials,
  stale state, replay, bridge-commitment tampering, cover tampering, and padding.
- `src/bin/benchmark.rs`: holder synchronization, public state, presentation,
  bottleneck, and credential-overhead benchmarks.
- `benchmarks/results/`: raw HiddenCover benchmark outputs used by the paper.
- `evaluation/`: baseline provenance, comparison patches, workloads, raw and
  normalized data, and numerical QA metadata.
- `scripts/analyze_and_plot.py`: normalization, assertions, tables, and figures.

The protocol implementation binds the credential-side hidden path node to the
cover-side membership proof through one Pedersen commitment. The transcript also
binds the state version, state digest, and verifier nonce.

## Requirements

- Rust 1.97.0 and Cargo (the artifact was tested with the GNU Windows target).
- Python 3.12 or later.
- Python packages listed in `requirements.txt`.
- For the cross-system reproduction only: Go 1.26 or later and the two baseline
  repositories listed in `evaluation/README.md`.

The checked-in `Cargo.lock` pins Rust dependencies. No network service, API key,
private dataset, or blockchain node is required for the HiddenCover tests and
benchmarks.

## Quick reproduction

From the repository root, run:

```bash
cargo test --locked --lib
cargo run --locked --release --bin benchmark -- benchmarks/results all
python -m pip install -r requirements.txt
python scripts/analyze_and_plot.py
```

On Windows, an ASCII-only build directory can avoid toolchain issues with long
or non-ASCII paths:

```powershell
$env:CARGO_TARGET_DIR='C:\artifact-build\hiddencover'
$env:RUSTFLAGS='-C target-cpu=native'
cargo +stable-x86_64-pc-windows-gnu test --locked --lib
cargo +stable-x86_64-pc-windows-gnu run --locked --release --bin benchmark -- benchmarks/results all
python -m pip install -r requirements.txt
python scripts/analyze_and_plot.py
```

The test command must finish with all tests passing. The benchmark command writes
CSV files under `benchmarks/results/`. The analysis script validates row counts
and proof-success flags, then exports normalized CSV files, tables, and figures
under `evaluation/`. See `evaluation/README.md` for the full RQ1--RQ4 workflow
and baseline-specific commands.

## Baseline provenance and comparison boundary

The artifact compares protocol components whose semantics can be aligned:

- ALLOSAUR, commit `5bf8724963529f6ca947316466ce38c0104a3dcf`.
- zkRevoke, commit `852f85846e98dd199289eeaa7943e19956a2649f`.

The corresponding modifications are recorded as patch files under
`evaluation/patches/`. External repositories are intentionally excluded from
this repository. Missing or non-comparable operations are represented as `NA`,
not as measured zero cost. The evaluation does not claim end-to-end equivalence
across deployments and excludes network latency, blockchain confirmation delay,
contract gas, and full multi-manager deployment latency.

## License

The artifact is released under the MIT License. The adapted one-out-of-many
structure follows the MIT-licensed `one-of-many-proofs` prototype; third-party
baseline repositories remain subject to their own licenses.
