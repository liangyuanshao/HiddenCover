"""Normalize comparison artifacts, validate measurements, and draw RQ1--RQ4 figures.

Figure contract
---------------
Core conclusion: HiddenCover removes per-holder private witness updates by moving
revocation cost into an authenticated public Cover and a Cover-dependent proof.
Figure archetype: quantitative grid.
Target/output: publication-quality figures; SVG primary, PDF/TIFF/PNG secondary.
Backend: Python only.
Evidence hierarchy: cross-system synchronization and public-state costs are hero
evidence; full current-state presentations are validation; internal breakdown and
credential overhead are mechanism/robustness evidence.
Statistics: median and interquartile range; n is stated for every panel.
Reviewer risk: protocol-semantic zeroes, non-equivalent wire encodings, and
different population constants must remain explicit.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.sans-serif"] = ["Arial", "DejaVu Sans", "Liberation Sans"]
plt.rcParams["svg.fonttype"] = "none"

import matplotlib as mpl
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarks" / "results"
EVAL = ROOT / "evaluation"
RAW = EVAL / "raw"
NORMALIZED = EVAL / "normalized"
METADATA = EVAL / "metadata"
FIGURES = EVAL / "figures"
TABLES = EVAL / "tables"
_allosaur_criterion = os.environ.get("HIDDENCOVER_ALLO_CRITERION")
ALLO_CRITERION = Path(_allosaur_criterion) if _allosaur_criterion else None

BLUE = "#0F4D92"
BLUE_2 = "#3775BA"
GREEN = "#3A8F5B"
RED = "#B64342"
VIOLET = "#7A5A9E"
BLACK = "#272727"
GRAY = "#767676"
LIGHT = "#D8D8D8"

DIST_STYLE = {
    "clustered": ("Clustered", GREEN, "s"),
    "random": ("Random", BLUE_2, "o"),
    "dispersed": ("Dispersed", RED, "^"),
}


def configure_style() -> None:
    mpl.rcParams.update(
        {
            "font.size": 7,
            "axes.labelsize": 7,
            "axes.titlesize": 7,
            "xtick.labelsize": 6.5,
            "ytick.labelsize": 6.5,
            "legend.fontsize": 6.2,
            "axes.linewidth": 0.8,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "lines.linewidth": 1.25,
            "lines.markersize": 3.5,
            "legend.frameon": False,
            "pdf.fonttype": 42,
            "savefig.dpi": 600,
        }
    )


def panel(ax: mpl.axes.Axes, label: str) -> None:
    ax.text(
        -0.16,
        1.04,
        label,
        transform=ax.transAxes,
        fontsize=8,
        fontweight="bold",
        va="bottom",
    )


def save(fig: mpl.figure.Figure, stem: str) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig.tight_layout(pad=0.65, w_pad=1.2)
    for suffix in ("svg", "pdf", "tiff", "png"):
        kwargs = {"bbox_inches": "tight"}
        if suffix in {"tiff", "png"}:
            kwargs["dpi"] = 600
        fig.savefig(FIGURES / f"{stem}.{suffix}", **kwargs)
    plt.close(fig)


def summary(frame: pd.DataFrame, groups: list[str], value: str) -> pd.DataFrame:
    return (
        frame.groupby(groups, dropna=False)[value]
        .agg(
            median="median",
            q25=lambda x: x.quantile(0.25),
            q75=lambda x: x.quantile(0.75),
            n="count",
        )
        .reset_index()
    )


def plot_band(ax, data, x, color, label, marker="o", linestyle="-") -> None:
    ax.plot(
        data[x],
        data["median"],
        color=color,
        label=label,
        marker=marker,
        linestyle=linestyle,
    )
    if len(data) > 1 and not np.allclose(data["q25"], data["q75"]):
        ax.fill_between(data[x], data["q25"], data["q75"], color=color, alpha=0.14)


def criterion_samples(operation: str, revoked: int) -> np.ndarray:
    assert ALLO_CRITERION is not None
    path = ALLO_CRITERION / f"{operation}_{revoked}" / "new" / "sample.json"
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    times = np.asarray(payload["times"], dtype=float)
    iters = np.asarray(payload["iters"], dtype=float)
    assert len(times) == 30 and len(iters) == 30
    return times / iters / 1e6


def normalize_allosaur() -> pd.DataFrame:
    cached = RAW / "allosaur" / "rq1_allosaur.csv"
    if ALLO_CRITERION is None:
        return pd.read_csv(cached)

    log = (RAW / "allosaur" / "comparison.log").read_text(
        encoding="utf-8", errors="replace"
    )
    messages = {
        int(d): (int(up), int(down))
        for d, up, down in re.findall(r"COMPARISON_CSV,(\d+),(\d+),(\d+)", log)
    }
    rows: list[dict[str, object]] = []
    for revoked in [10, 30, 100, 300, 1000, 3000, 10000]:
        pre = criterion_samples("allosaur user-side pre-update", revoked)
        post = criterion_samples("user-side post-update", revoked)
        server = criterion_samples("allosaur server-side update", revoked)
        upload, download = messages[revoked]
        for measurement in range(30):
            rows.append(
                {
                    "scheme": "ALLOSAUR",
                    "capacity": 16384,
                    "revoked": revoked,
                    "distribution": "not_applicable",
                    "workload_seed": np.nan,
                    "measurement": measurement,
                    "cover_nodes": np.nan,
                    "holder_upload_bytes": upload,
                    "holder_download_bytes": download,
                    "holder_compute_ms": pre[measurement] + post[measurement],
                    "server_per_holder_ms": server[measurement],
                    "verified": True,
                    "zero_semantics": "none",
                }
            )
    frame = pd.DataFrame(rows)
    frame.to_csv(RAW / "allosaur" / "rq1_allosaur.csv", index=False)
    return frame


def normalize() -> dict[str, pd.DataFrame]:
    NORMALIZED.mkdir(parents=True, exist_ok=True)
    (RAW / "hiddencover").mkdir(parents=True, exist_ok=True)
    for name in (
        "rq1_hiddencover.csv",
        "rq2_hiddencover.csv",
        "rq3_rq4_hiddencover.csv",
        "credential_hiddencover.csv",
    ):
        shutil.copy2(RESULTS / name, RAW / "hiddencover" / name)

    hidden_rq1 = pd.read_csv(RESULTS / "rq1_hiddencover.csv")
    hidden_rq1["zero_semantics"] = (
        "no private request; no individualized server witness update"
    )
    allosaur = normalize_allosaur()
    rq1 = pd.concat([hidden_rq1, allosaur], ignore_index=True, sort=False)
    rq1.to_csv(NORMALIZED / "rq1_sync.csv", index=False)

    hidden_rq2 = pd.read_csv(RESULTS / "rq2_hiddencover.csv")
    hidden_rq2["measurement"] = hidden_rq2["workload_seed"]
    hidden_rq2["state_semantics"] = "authenticated Complete-Subtree Cover"
    zk_rq2 = pd.read_csv(RAW / "zkRevoke" / "rq2_zkrevoke.csv")
    zk_rq2["distribution"] = "not_applicable"
    zk_rq2["workload_seed"] = np.nan
    zk_rq2["cover_nodes"] = np.nan
    zk_rq2["state_semantics"] = "epoch and bytes32 token blacklist"
    rq2 = pd.concat([hidden_rq2, zk_rq2], ignore_index=True, sort=False)
    rq2.to_csv(NORMALIZED / "rq2_state.csv", index=False)

    hidden_rq3 = pd.read_csv(RESULTS / "rq3_rq4_hiddencover.csv")
    hidden_rq3["protocol_payload_bytes"] = hidden_rq3["presentation_bytes"]
    hidden_rq3["m"] = np.nan
    hidden_rq3["k"] = np.nan
    hidden_rq3["revoked"] = np.nan
    hidden_rq3["json_wire_bytes"] = np.nan
    hidden_rq3["proof_bytes"] = hidden_rq3["presentation_bytes"]
    zk_rq3 = pd.read_csv(RAW / "zkRevoke" / "rq3_zkrevoke.csv")
    zk_rq3["cover_nodes"] = np.nan
    zk_rq3["padded_set_size"] = np.nan
    for column in (
        "state_check_ms",
        "match_ms",
        "credential_bridge_ms",
        "cover_transform_ms",
        "oom_ms",
    ):
        zk_rq3[column] = np.nan
    rq3 = pd.concat([hidden_rq3, zk_rq3], ignore_index=True, sort=False)
    rq3.to_csv(NORMALIZED / "rq3_presentation.csv", index=False)

    rq4 = hidden_rq3.copy()
    rq4.to_csv(NORMALIZED / "rq4_breakdown.csv", index=False)
    credential = pd.read_csv(RESULTS / "credential_hiddencover.csv")
    credential.to_csv(NORMALIZED / "credential_overhead.csv", index=False)
    return {"rq1": rq1, "rq2": rq2, "rq3": rq3, "rq4": rq4, "credential": credential}


def draw_rq1(frame: pd.DataFrame) -> None:
    hidden = frame[frame["scheme"] == "HiddenCover"]
    allo = frame[frame["scheme"] == "ALLOSAUR"]
    fig, axes = plt.subplots(1, 3, figsize=(7.08, 2.25))

    ax = axes[0]
    a = summary(allo, ["revoked"], "holder_upload_bytes")
    h = summary(hidden, ["revoked"], "holder_upload_bytes")
    plot_band(ax, a, "revoked", VIOLET, "ALLOSAUR", "o")
    plot_band(ax, h, "revoked", BLUE, "HiddenCover", "s")
    ax.set_xscale("log")
    ax.set_xlabel("Revocations per update")
    ax.set_ylabel("Holder upload (bytes)")
    ax.legend(loc="upper left")
    panel(ax, "a")

    ax = axes[1]
    for distribution, (label, color, marker) in DIST_STYLE.items():
        data = summary(
            hidden[hidden["distribution"] == distribution],
            ["revoked"],
            "holder_download_bytes",
        )
        plot_band(ax, data, "revoked", color, f"HiddenCover: {label}", marker)
    a = summary(allo, ["revoked"], "holder_download_bytes")
    plot_band(ax, a, "revoked", VIOLET, "ALLOSAUR", "D", "--")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Revocations per update")
    ax.set_ylabel("State/update download (bytes)")
    ax.legend(loc="upper left", fontsize=5.4)
    panel(ax, "b")

    ax = axes[2]
    data = summary(
        hidden[hidden["distribution"] == "random"],
        ["revoked"],
        "holder_compute_ms",
    )
    plot_band(ax, data, "revoked", BLUE, "HiddenCover state sync", "s")
    data = summary(allo, ["revoked"], "holder_compute_ms")
    plot_band(ax, data, "revoked", VIOLET, "ALLOSAUR holder", "o")
    data = summary(allo, ["revoked"], "server_per_holder_ms")
    plot_band(ax, data, "revoked", BLACK, "ALLOSAUR server/holder", "D", "--")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Revocations per update")
    ax.set_ylabel("Computation (ms)")
    ax.text(
        0.98,
        0.04,
        "HiddenCover server/holder = 0",
        transform=ax.transAxes,
        ha="right",
        color=BLUE,
        fontsize=5.6,
    )
    ax.legend(loc="upper left", fontsize=5.4)
    panel(ax, "c")
    save(fig, "rq1_holder_synchronization")


def draw_rq2(frame: pd.DataFrame) -> None:
    hidden = frame[frame["scheme"] == "HiddenCover"].copy()
    zk = frame[frame["scheme"] == "zkRevoke"].copy()
    hidden["rate_pct"] = hidden["rate"] * 100
    zk["rate_pct"] = zk["rate"] * 100
    fig, axes = plt.subplots(1, 3, figsize=(7.08, 2.25))

    ax = axes[0]
    for distribution, (label, color, marker) in DIST_STYLE.items():
        data = summary(
            hidden[hidden["distribution"] == distribution],
            ["rate_pct"],
            "public_state_bytes",
        )
        data[["median", "q25", "q75"]] /= 2**20
        plot_band(ax, data, "rate_pct", color, f"HiddenCover: {label}", marker)
    data = summary(zk, ["rate_pct"], "public_state_bytes")
    data[["median", "q25", "q75"]] /= 2**20
    plot_band(ax, data, "rate_pct", BLACK, "zkRevoke blacklist", "D", "--")
    ax.axhline(48 / 2**20, color=VIOLET, linestyle=":", label="ALLOSAUR accumulator")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Revoked credentials (%)")
    ax.set_ylabel("Public state (MiB)")
    ax.legend(loc="upper left", fontsize=5.2)
    panel(ax, "a")

    ax = axes[1]
    for distribution, (label, color, marker) in DIST_STYLE.items():
        data = summary(
            hidden[hidden["distribution"] == distribution],
            ["rate_pct"],
            "authority_refresh_ms",
        )
        plot_band(ax, data, "rate_pct", color, f"HiddenCover: {label}", marker)
    data = summary(zk, ["rate_pct"], "authority_refresh_ms")
    plot_band(ax, data, "rate_pct", BLACK, "zkRevoke", "D", "--")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Revoked credentials (%)")
    ax.set_ylabel("Authority refresh (ms)")
    panel(ax, "b")

    ax = axes[2]
    hidden["compression"] = hidden["revoked"] / hidden["cover_nodes"]
    for distribution, (label, color, marker) in DIST_STYLE.items():
        data = summary(
            hidden[hidden["distribution"] == distribution],
            ["rate_pct"],
            "compression",
        )
        plot_band(ax, data, "rate_pct", color, label, marker)
    ax.axhline(1, color=BLACK, linestyle="--", linewidth=0.8)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Revoked credentials (%)")
    ax.set_ylabel(r"Compression $D/|\mathcal{S}_t|$")
    panel(ax, "c")
    save(fig, "rq2_public_state_transfer")


def draw_rq3(frame: pd.DataFrame) -> None:
    hidden = frame[frame["scheme"] == "HiddenCover"].copy()
    zk = frame[frame["scheme"] == "zkRevoke"].copy()
    fig, axes = plt.subplots(1, 3, figsize=(7.08, 2.25))
    metrics = [
        ("protocol_payload_bytes", "Protocol payload (KiB)", 1 / 1024),
        ("show_ms", "Presentation generation (ms)", 1),
        ("verify_ms", "Verification (ms)", 1),
    ]
    for idx, (metric, ylabel, factor) in enumerate(metrics):
        ax = axes[idx]
        data = summary(hidden, ["cover_nodes"], metric)
        data[["median", "q25", "q75"]] *= factor
        plot_band(ax, data, "cover_nodes", BLUE, "HiddenCover", "o")
        z = summary(zk, ["scheme"], metric).iloc[0]
        ax.axhline(z["median"] * factor, color=VIOLET, linestyle="--", label="zkRevoke")
        ax.axhspan(z["q25"] * factor, z["q75"] * factor, color=VIOLET, alpha=0.12)
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xlabel("HiddenCover Cover nodes")
        ax.set_ylabel(ylabel)
        if idx == 0:
            ax.legend(loc="upper left")
        panel(ax, chr(ord("a") + idx))
    save(fig, "rq3_current_state_presentation")


def draw_rq4(frame: pd.DataFrame) -> None:
    components = [
        ("state_check_ms", "State authentication", GRAY),
        ("match_ms", "Path/Cover match", GREEN),
        ("credential_bridge_ms", "Credential + bridge", VIOLET),
        ("cover_transform_ms", "Cover transform", RED),
        ("oom_ms", "One-out-of-Many", BLUE),
    ]
    x = sorted(frame["cover_nodes"].unique())
    medians = {
        column: frame.groupby("cover_nodes")[column].median().reindex(x).to_numpy()
        for column, _, _ in components
    }
    total = frame.groupby("cover_nodes")["show_ms"].median().reindex(x).to_numpy()
    fig, axes = plt.subplots(1, 2, figsize=(7.08, 2.25))

    ax = axes[0]
    for column, label, color in components:
        ax.plot(x, medians[column], marker="o", color=color, label=label)
    ax.plot(x, total, color=BLACK, linestyle="--", label="Total Show")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("Cover nodes")
    ax.set_ylabel("Component time (ms)")
    ax.legend(loc="upper left", ncol=2, fontsize=5.4)
    panel(ax, "a")

    ax = axes[1]
    matrix = np.vstack([medians[column] for column, _, _ in components])
    shares = matrix / matrix.sum(axis=0, keepdims=True) * 100
    ax.stackplot(
        x,
        shares,
        labels=[label for _, label, _ in components],
        colors=[color for _, _, color in components],
        alpha=0.9,
    )
    ax.set_xscale("log", base=2)
    ax.set_ylim(0, 100)
    ax.set_xlabel("Cover nodes")
    ax.set_ylabel("Measured Show components (%)")
    panel(ax, "b")
    save(fig, "rq4_hiddencover_bottleneck")


def write_tables(frames: dict[str, pd.DataFrame]) -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    cred = (
        frames["credential"]
        .groupby(["depth", "capacity"])
        .agg(
            path_signatures=("path_signatures", "median"),
            credential_bytes=("credential_bytes", "median"),
            issue_ms_median=("issue_ms", "median"),
            issue_ms_q25=("issue_ms", lambda x: x.quantile(0.25)),
            issue_ms_q75=("issue_ms", lambda x: x.quantile(0.75)),
            n=("issue_ms", "count"),
        )
        .reset_index()
    )
    cred.to_csv(TABLES / "credential_overhead.csv", index=False)
    lines = [
        "| $d$ | 最大容量 $N$ | 路径签名数 | 凭证大小（B） | 签发时间中位数 [IQR]（ms） |",
        "|---:|---:|---:|---:|---:|",
    ]
    for row in cred.itertuples():
        lines.append(
            f"| {row.depth} | $2^{{{row.depth}}}$ | {int(row.path_signatures)} | "
            f"{int(row.credential_bytes)} | {row.issue_ms_median:.2f} "
            f"[{row.issue_ms_q25:.2f}, {row.issue_ms_q75:.2f}] |"
        )
    (TABLES / "credential_overhead.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def validate_and_summarize(frames: dict[str, pd.DataFrame]) -> dict[str, object]:
    assert len(frames["rq1"].query("scheme == 'HiddenCover'")) == 12600
    assert len(frames["rq1"].query("scheme == 'ALLOSAUR'")) == 210
    assert len(frames["rq2"].query("scheme == 'HiddenCover'")) == 300
    assert len(frames["rq2"].query("scheme == 'zkRevoke'")) == 150
    assert len(frames["rq3"].query("scheme == 'HiddenCover'")) == 300
    assert len(frames["rq3"].query("scheme == 'zkRevoke'")) == 30
    for name in ("rq1", "rq2", "rq3"):
        verified = frames[name]["verified"].astype(str).str.lower()
        assert (verified == "true").all(), f"{name} contains failed samples"

    rq1h = frames["rq1"].query("scheme == 'HiddenCover'")
    rq1a = frames["rq1"].query("scheme == 'ALLOSAUR'")
    rq2h = frames["rq2"].query("scheme == 'HiddenCover'")
    rq2z = frames["rq2"].query("scheme == 'zkRevoke'")
    rq3h = frames["rq3"].query("scheme == 'HiddenCover'")
    rq3z = frames["rq3"].query("scheme == 'zkRevoke'")
    at_d = lambda frame, d: frame[frame["revoked"] == d]
    at_rate = lambda frame, r: frame[np.isclose(frame["rate"], r)]
    at_cover = lambda m: rq3h[rq3h["cover_nodes"] == m]
    report: dict[str, object] = {
        "row_counts": {name: len(frame) for name, frame in frames.items()},
        "rq1_at_1000": {
            "allosaur_total_bytes_median": float(
                (
                    at_d(rq1a, 1000)["holder_upload_bytes"]
                    + at_d(rq1a, 1000)["holder_download_bytes"]
                ).median()
            ),
            "allosaur_holder_ms_median": float(
                at_d(rq1a, 1000)["holder_compute_ms"].median()
            ),
            "allosaur_server_ms_median": float(
                at_d(rq1a, 1000)["server_per_holder_ms"].median()
            ),
            "hidden_random_state_bytes_median": float(
                at_d(rq1h.query("distribution == 'random'"), 1000)[
                    "holder_download_bytes"
                ].median()
            ),
            "hidden_random_sync_ms_median": float(
                at_d(rq1h.query("distribution == 'random'"), 1000)[
                    "holder_compute_ms"
                ].median()
            ),
        },
        "rq2_at_1pct": {
            "hidden_state_bytes": {
                d: float(
                    at_rate(rq2h[rq2h["distribution"] == d], 0.01)[
                        "public_state_bytes"
                    ].median()
                )
                for d in DIST_STYLE
            },
            "hidden_refresh_ms": {
                d: float(
                    at_rate(rq2h[rq2h["distribution"] == d], 0.01)[
                        "authority_refresh_ms"
                    ].median()
                )
                for d in DIST_STYLE
            },
            "zk_state_bytes": float(
                at_rate(rq2z, 0.01)["public_state_bytes"].median()
            ),
            "zk_refresh_ms": float(
                at_rate(rq2z, 0.01)["authority_refresh_ms"].median()
            ),
        },
        "rq3": {
            "zk_payload_bytes": float(rq3z["protocol_payload_bytes"].median()),
            "zk_json_bytes": float(rq3z["json_wire_bytes"].median()),
            "zk_show_ms": float(rq3z["show_ms"].median()),
            "zk_verify_ms": float(rq3z["verify_ms"].median()),
            "hidden_64": {
                "payload_bytes": float(at_cover(64)["protocol_payload_bytes"].median()),
                "show_ms": float(at_cover(64)["show_ms"].median()),
                "verify_ms": float(at_cover(64)["verify_ms"].median()),
            },
            "hidden_1024": {
                "payload_bytes": float(
                    at_cover(1024)["protocol_payload_bytes"].median()
                ),
                "show_ms": float(at_cover(1024)["show_ms"].median()),
                "verify_ms": float(at_cover(1024)["verify_ms"].median()),
            },
            "hidden_4096": {
                "payload_bytes": float(
                    at_cover(4096)["protocol_payload_bytes"].median()
                ),
                "show_ms": float(at_cover(4096)["show_ms"].median()),
                "verify_ms": float(at_cover(4096)["verify_ms"].median()),
                "oom_share_pct": float(
                    (
                        at_cover(4096)["oom_ms"]
                        / (
                            at_cover(4096)[
                                [
                                    "state_check_ms",
                                    "match_ms",
                                    "credential_bridge_ms",
                                    "cover_transform_ms",
                                    "oom_ms",
                                ]
                            ].sum(axis=1)
                        )
                        * 100
                    ).median()
                ),
            },
        },
    }
    METADATA.mkdir(parents=True, exist_ok=True)
    (METADATA / "data_qa.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return report


def write_figure_qa() -> None:
    rows = []
    for stem in (
        "rq1_holder_synchronization",
        "rq2_public_state_transfer",
        "rq3_current_state_presentation",
        "rq4_hiddencover_bottleneck",
    ):
        svg = FIGURES / f"{stem}.svg"
        text = svg.read_text(encoding="utf-8")
        rows.append(
            {
                "figure": stem,
                "svg_text_editable": "<text" in text,
                "svg_bytes": svg.stat().st_size,
                "pdf_exists": (FIGURES / f"{stem}.pdf").exists(),
                "tiff_exists": (FIGURES / f"{stem}.tiff").exists(),
                "png_exists": (FIGURES / f"{stem}.png").exists(),
            }
        )
    pd.DataFrame(rows).to_csv(METADATA / "figure_qa.csv", index=False)
    assert all(row["svg_text_editable"] for row in rows)


def main() -> None:
    configure_style()
    frames = normalize()
    validate_and_summarize(frames)
    draw_rq1(frames["rq1"])
    draw_rq2(frames["rq2"])
    draw_rq3(frames["rq3"])
    draw_rq4(frames["rq4"])
    write_tables(frames)
    write_figure_qa()
    print(f"normalized data: {NORMALIZED}")
    print(f"figures: {FIGURES}")


if __name__ == "__main__":
    main()
