# Evaluation environment

- Date: 2026-08-20 (Asia/Shanghai).
- OS: Microsoft Windows 11 Pro, version 10.0.22631, build 22631.
- CPU: 12th Gen Intel Core i5-12400F, 6 cores / 12 logical processors.
- Memory: 31.8 GiB.
- Rust: rustc 1.97.0; cargo 1.97.0; GNU Windows target.
- Go: 1.26.5 windows/amd64.
- Python: 3.12.10.
- HiddenCover revision: initial public artifact release.
- ALLOSAUR commit: 5bf8724963529f6ca947316466ce38c0104a3dcf.
- zkRevoke commit: 852f85846e98dd199289eeaa7943e19956a2649f.

HiddenCover was compiled in release mode with thin LTO, one codegen unit and
-C target-cpu=native. ALLOSAUR used Criterion's default three-second warm-up
phase and 30 measured samples. zkRevoke and HiddenCover used
five explicit warm-up iterations and 30 measured iterations where applicable.
