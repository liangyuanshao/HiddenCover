# HiddenCover cross-system evaluation

This directory contains the reproducible RQ1--RQ4 comparison harness.

## Baseline provenance

- ALLOSAUR: https://github.com/sam-jaques/allosaurust, commit 5bf8724963529f6ca947316466ce38c0104a3dcf.
- zkRevoke: https://github.com/praveensankar/zkRevoke, commit 852f85846e98dd199289eeaa7943e19956a2649f.

The external repositories are kept under external/ and are excluded from the
HiddenCover Git repository. Apply the files in patches/ after checking out the
commits above. The ALLOSAUR patch also records the local pin required because
core2 0.4.0 is yanked and the upstream repository has no lockfile.

## Data layout

- raw/hiddencover: raw Rust benchmark CSVs.
- raw/allosaur: Criterion console log and per-sample normalized CSV.
- raw/zkRevoke: comparison-mode CSVs from the official Go implementation.
- normalized: unified RQ1--RQ4 datasets. Missing, non-comparable fields are NA;
  zero is used only when a protocol step is absent by construction.
- metadata: environment, numerical QA and figure QA.
- workloads: workload parameters and deterministic seed rules.

## Reproduction

1. Run the Rust unit tests and benchmark modes rq1, rq2, rq3 and credential.
2. Apply allosaur-comparison.patch and run the updated Criterion benchmark.
3. Apply zkRevoke-comparison.patch and run cmd/hiddencover_compare.
4. Run scripts/analyze_and_plot.py with the project Python environment.

The Python script copies raw HiddenCover CSVs, normalizes all three artifacts,
asserts row counts and proof success, and exports SVG/PDF/TIFF/PNG figures and
CSV/Markdown tables under evaluation/.
Network latency, blockchain confirmation latency, contract gas and the complete
multi-manager deployment latency are outside the measured scope.
