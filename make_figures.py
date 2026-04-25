#!/usr/bin/env python3
import argparse
import hashlib
import math
import re
from pathlib import Path
from typing import Optional, Dict, List, Tuple

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scapy.utils import PcapNgReader

ETH_GOOSE = 0x88B8
ETH_SV    = 0x88BA

# 2-sided 95% CI t-critical values for df=1..30 (0.975 quantile)
T975 = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262,
    10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131, 16: 2.120, 17: 2.110,
    18: 2.101, 19: 2.093, 20: 2.086, 21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
    26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
}

STAT_KEYS = ["median", "p95", "p99", "mean", "std", "min", "max"]
# Scalar metrics (we only use 'mean' for them; still stored in same schema)
SCALAR_METRICS = {"SV_rate_pkts_per_sec", "GOOSE_delivery_ratio", "SV_loss_proxy"}

def mac_fmt(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b).lower()

def parse_packet(pkt) -> Optional[dict]:
    b = bytes(pkt)
    if len(b) < 14:
        return None

    dst = mac_fmt(b[0:6])
    src = mac_fmt(b[6:12])
    tpid = int.from_bytes(b[12:14], "big")

    if tpid == 0x8100 and len(b) >= 18:
        ethertype = int.from_bytes(b[16:18], "big")
        payload_offset = 18
    else:
        ethertype = tpid
        payload_offset = 14

    appid = None
    if ethertype in (ETH_GOOSE, ETH_SV) and len(b) >= payload_offset + 2:
        appid = int.from_bytes(b[payload_offset:payload_offset + 2], "big")

    h = hashlib.sha1(b).hexdigest()

    return {
        "t": float(pkt.time),
        "len": len(b),
        "src": src,
        "dst": dst,
        "ethertype": ethertype,
        "appid": appid,
        "hash": h,
    }

def read_pcap_df(path: Path) -> pd.DataFrame:
    rows = []
    with PcapNgReader(str(path)) as rdr:
        for pkt in rdr:
            d = parse_packet(pkt)
            if d:
                rows.append(d)
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    return df.sort_values("t")


def _candidate_pcaps(run_dir: Path) -> List[Path]:
    """Return all pcap/pcapng/cap files under run_dir (recursive)."""
    exts = {".pcapng", ".pcap", ".cap"}
    return [p for p in run_dir.rglob("*") if p.is_file() and p.suffix.lower() in exts]


def find_iface_pcap(run_dir: Path, iface: str) -> Path:
    """
    Robustly locate the pcap for a given iface within a run directory.

    Strategy:
      1) Search recursively for pcap/pcapng/cap under run_dir
      2) Prefer filename matches for iface variants (DPSRS-eth4, DPSRS_eth4, etc.)
      3) If no direct match, try matching just ethX (e.g., eth4)
      4) If still no match, fall back to the largest pcap (and print which file was chosen)
    """
    cands = _candidate_pcaps(run_dir)
    if not cands:
        raise FileNotFoundError(f"No pcap/pcapng found anywhere under {run_dir}")

    iface_l = iface.strip().lower()
    variants = {
        iface_l,
        iface_l.replace("-", "_"),
        iface_l.replace("_", "-"),
        iface_l.replace("-", ""),
        iface_l.replace("_", ""),
    }

    m_eth = re.search(r"(eth\d+)", iface_l)
    eth = m_eth.group(1) if m_eth else ""

    narrowed = [p for p in cands if eth and eth in p.name.lower()]
    pool = narrowed if narrowed else cands

    def score(p: Path) -> int:
        name = p.name.lower()
        s = 0
        if any(v and v in name for v in variants):
            s += 200
        if eth and eth in name:
            s += 50
        if p.parent == run_dir:
            s += 10
        s += min(int(p.stat().st_size // 1_000_000), 50)
        return s

    ranked = sorted(pool, key=lambda p: (score(p), p.stat().st_size, p.as_posix()), reverse=True)
    best = ranked[0]
    best_score = score(best)

    if best_score >= 60:
        print(f"[pcap] {run_dir.name}: iface '{iface}' -> {best}")
        return best

    largest = max(cands, key=lambda p: p.stat().st_size)
    print(f"[pcap][fallback] {run_dir.name}: iface '{iface}' -> {largest}")
    return largest


def _to_series(x) -> pd.Series:
    """Convert array-like/Series to a clean float Series (safe for numpy arrays)."""
    if x is None:
        return pd.Series([], dtype=float)
    if isinstance(x, pd.Series):
        s = x
    else:
        try:
            s = pd.Series(x)
        except Exception:
            s = pd.Series([x])
    s = pd.to_numeric(s, errors="coerce")
    return s.astype(float)

def summarize(series) -> Optional[dict]:
    s = _to_series(series).dropna().values
    if s.size == 0:
        return None
    return {
        "n": int(s.size),
        "median": float(np.percentile(s, 50)),
        "p95": float(np.percentile(s, 95)),
        "p99": float(np.percentile(s, 99)),
        "min": float(np.min(s)),
        "max": float(np.max(s)),
        "mean": float(np.mean(s)),
        "std": float(np.std(s, ddof=0)),
    }

def ecdf(series):
    s = _to_series(series).dropna().sort_values().values
    if len(s) == 0:
        return [], []
    y = [(i + 1) / len(s) for i in range(len(s))]
    return s, y

def interarrival_ms_per_publisher(df: pd.DataFrame, ethertype: int, dedup_ms: float = 0.0) -> Dict[str, pd.Series]:
    d = df[df["ethertype"] == ethertype].copy()
    out: Dict[str, pd.Series] = {}
    for src, g in d.groupby("src"):
        t = g["t"].values
        if len(t) < 2:
            out[src] = pd.Series([], dtype=float)
            continue
        deltas = (t[1:] - t[:-1]) * 1000.0
        if dedup_ms > 0:
            deltas = deltas[deltas >= dedup_ms]
        out[src] = pd.Series(deltas, dtype=float)
    return out

def interarrival_ms_aggregated(df: pd.DataFrame, ethertype: int, dedup_ms: float = 0.0) -> pd.Series:
    per = interarrival_ms_per_publisher(df, ethertype, dedup_ms)
    series = [s for s in per.values() if not s.empty]
    return pd.concat(series, ignore_index=True) if series else pd.Series([], dtype=float)

def match_latency_ms(df_uplink: pd.DataFrame, df_hmi: pd.DataFrame, ethertype: int) -> pd.Series:
    u = df_uplink[df_uplink["ethertype"] == ethertype].dropna(subset=["hash"]).copy()
    h = df_hmi[df_hmi["ethertype"] == ethertype].dropna(subset=["hash"]).copy()
    if u.empty or h.empty:
        return pd.Series([], dtype=float)

    u_first = u.groupby("hash")["t"].min()
    h_first = h.groupby("hash")["t"].min()
    common = u_first.index.intersection(h_first.index)
    if len(common) == 0:
        return pd.Series([], dtype=float)

    lat = (h_first.loc[common].values - u_first.loc[common].values) * 1000.0
    lat = [v for v in lat if v >= 0.0 and v < 10_000]
    return pd.Series(lat, dtype=float)

def delivery_ratio(df_uplink: pd.DataFrame, df_hmi: pd.DataFrame, ethertype: int) -> float:
    u = set(df_uplink[df_uplink["ethertype"] == ethertype]["hash"].tolist())
    h = set(df_hmi[df_hmi["ethertype"] == ethertype]["hash"].tolist())
    return (len(u & h) / len(u)) if len(u) else float("nan")

def rate_per_sec(df: pd.DataFrame, ethertype: int) -> float:
    if df.empty:
        return float("nan")
    dur = df["t"].max() - df["t"].min()
    if dur <= 0:
        return float("nan")
    return float((df["ethertype"] == ethertype).sum()) / dur

def ci95_mean(values: List[float]) -> Tuple[float, float, float]:
    x = np.array([v for v in values if v is not None and not (isinstance(v, float) and math.isnan(v))], dtype=float)
    n = x.size
    if n == 0:
        return (float("nan"), float("nan"), float("nan"))
    mu = float(np.mean(x))
    if n == 1:
        return (mu, mu, mu)
    s = float(np.std(x, ddof=1))
    se = s / math.sqrt(n)
    df = n - 1
    t = T975.get(df, 1.96)
    half = t * se
    return (mu, mu - half, mu + half)

def run_ids(prefix: str, start: int, end: int) -> List[str]:
    return [f"{prefix}{i:03d}" for i in range(start, end + 1)]

def parse_run_index(run_id: str) -> Optional[int]:
    try:
        return int(run_id.split("_")[-1])
    except Exception:
        return None

def compute_run_metrics(run_dir: Path, hmi_iface: str, uplink_iface: str, dedup_ms: float) -> dict:
    hmi_p = find_iface_pcap(run_dir, hmi_iface)
    upl_p = find_iface_pcap(run_dir, uplink_iface)

    df_h = read_pcap_df(hmi_p)
    df_u = read_pcap_df(upl_p)

    sv_per = interarrival_ms_per_publisher(df_h, ETH_SV, dedup_ms)
    sv_agg = interarrival_ms_aggregated(df_h, ETH_SV, dedup_ms)

    goose_ia_per = interarrival_ms_per_publisher(df_h, ETH_GOOSE, dedup_ms)
    goose_ia_agg = interarrival_ms_aggregated(df_h, ETH_GOOSE, dedup_ms)

    goose_lat = match_latency_ms(df_u, df_h, ETH_GOOSE)
    goose_dr  = delivery_ratio(df_u, df_h, ETH_GOOSE)

    sv_rate = rate_per_sec(df_h, ETH_SV)

    return {
        "df_hmi": df_h,
        "df_uplink": df_u,
        "sv_per": sv_per,
        "sv_agg": sv_agg,
        "goose_ia_per": goose_ia_per,
        "goose_ia_agg": goose_ia_agg,
        "goose_lat": goose_lat,
        "goose_dr": goose_dr,
        "sv_rate": sv_rate,
        "hmi_pcap": str(hmi_p),
        "uplink_pcap": str(upl_p),
    }

def rows_from_envelopes(case: str, run: str, metric: str, per: Dict[str, pd.Series], agg: pd.Series) -> List[dict]:
    rows = []
    for pub, series in per.items():
        st = summarize(series) or {"n": 0}
        rows.append({
            "value_type": "raw",
            "row_type": "per_run",
            "case": case,
            "run": run,
            "metric": metric,
            "scope": "publisher",
            "publisher": pub,
            **st
        })
    st_agg = summarize(agg) or {"n": 0}
    rows.append({
        "value_type": "raw",
        "row_type": "per_run",
        "case": case,
        "run": run,
        "metric": metric,
        "scope": "aggregated",
        "publisher": "ALL",
        **st_agg
    })
    return rows

def scalar_row(case: str, run: str, metric: str, value: float) -> dict:
    return {
        "value_type": "raw",
        "row_type": "per_run",
        "case": case,
        "run": run,
        "metric": metric,
        "scope": "aggregated",
        "publisher": "ALL",
        "n": 1,
        "mean": value,
    }

def summary_rows_from_perrun(df_per_run: pd.DataFrame, case: str, metric: str, scope: str, publisher: str) -> Optional[dict]:
    sub = df_per_run[
        (df_per_run["value_type"] == "raw") &
        (df_per_run["row_type"] == "per_run") &
        (df_per_run["case"] == case) &
        (df_per_run["metric"] == metric) &
        (df_per_run["scope"] == scope) &
        (df_per_run["publisher"] == publisher)
    ]
    if sub.empty:
        return None

    recs = sub.to_dict("records")
    out = {
        "value_type": "raw",
        "row_type": "summary_mean_ci95",
        "case": case,
        "run": "ALL",
        "metric": metric,
        "scope": scope,
        "publisher": publisher,
        "k_runs": len(recs),
    }

    if metric in SCALAR_METRICS:
        vals = [r.get("mean", float("nan")) for r in recs]
        mu, lo, hi = ci95_mean(vals)
        out["mean_mean"] = mu
        out["mean_ci95_low"] = lo
        out["mean_ci95_high"] = hi
        return out

    for k in STAT_KEYS:
        vals = [r.get(k, float("nan")) for r in recs]
        mu, lo, hi = ci95_mean(vals)
        out[f"{k}_mean"] = mu
        out[f"{k}_ci95_low"] = lo
        out[f"{k}_ci95_high"] = hi

    n_vals = [r.get("n", 0) for r in recs]
    out["n_mean"] = float(np.mean(n_vals)) if n_vals else float("nan")
    return out

def paired_delta_rows(perrun_raw: pd.DataFrame, baseline_prefix: str, defense_prefix: str) -> pd.DataFrame:
    base = perrun_raw[perrun_raw["case"] == "baseline"].copy()
    deff = perrun_raw[perrun_raw["case"] == "defense"].copy()

    base["idx"] = base["run"].apply(parse_run_index)
    deff["idx"] = deff["run"].apply(parse_run_index)

    join_cols = ["idx", "metric", "scope", "publisher"]
    b = base[["idx", "metric", "scope", "publisher", "n"] + STAT_KEYS].copy()
    d = deff[["idx", "metric", "scope", "publisher", "n"] + STAT_KEYS].copy()

    merged = pd.merge(d, b, on=join_cols, suffixes=("_def", "_base"), how="inner")

    delta_rows = []
    for _, r in merged.iterrows():
        metric = r["metric"]
        row = {
            "value_type": "delta",
            "row_type": "per_run",
            "case": "defense_minus_baseline",
            "run": f"{int(r['idx']):03d}" if pd.notna(r["idx"]) else "",
            "metric": metric,
            "scope": r["scope"],
            "publisher": r["publisher"],
        }

        if metric in SCALAR_METRICS:
            row["n"] = 1
            row["mean"] = (r.get("mean_def", np.nan) - r.get("mean_base", np.nan))
        else:
            row["n"] = r.get("n_def", np.nan)
            for k in STAT_KEYS:
                row[k] = (r.get(f"{k}_def", np.nan) - r.get(f"{k}_base", np.nan))
            row["mean"] = (r.get("mean_def", np.nan) - r.get("mean_base", np.nan))
        delta_rows.append(row)

    df_delta_perrun = pd.DataFrame(delta_rows)

    summary_rows = []
    if not df_delta_perrun.empty:
        for (metric, scope, publisher), g in df_delta_perrun.groupby(["metric", "scope", "publisher"]):
            out = {
                "value_type": "delta",
                "row_type": "summary_mean_ci95",
                "case": "defense_minus_baseline",
                "run": "ALL",
                "metric": metric,
                "scope": scope,
                "publisher": publisher,
                "k_runs": int(g["run"].nunique()),
            }
            if metric in SCALAR_METRICS:
                vals = g["mean"].tolist()
                mu, lo, hi = ci95_mean(vals)
                out["mean_mean"] = mu
                out["mean_ci95_low"] = lo
                out["mean_ci95_high"] = hi
            else:
                for k in STAT_KEYS:
                    vals = g[k].tolist() if k in g.columns else []
                    mu, lo, hi = ci95_mean(vals)
                    out[f"{k}_mean"] = mu
                    out[f"{k}_ci95_low"] = lo
                    out[f"{k}_ci95_high"] = hi
            summary_rows.append(out)

    df_delta_summary = pd.DataFrame(summary_rows)
    return pd.concat([df_delta_perrun, df_delta_summary], ignore_index=True, sort=False)

# -------------------------- Multi-attack helpers --------------------------

def _infer_attacker_mac(df_att: pd.DataFrame) -> str:
    if df_att.empty or "src" not in df_att.columns:
        return ""
    counts = df_att["src"].dropna().astype(str).str.lower().value_counts()
    inferred = ""
    for mac in counts.index:
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        try:
            first_octet = int(mac.split(":")[0], 16)
            if first_octet & 1:
                continue
        except Exception:
            pass
        inferred = mac
        break
    if not inferred and len(counts.index) > 0:
        inferred = str(counts.index[0]).lower()
    return inferred

def _pps_series(df: pd.DataFrame, src_mac: str) -> pd.Series:
    if df.empty:
        return pd.Series([], dtype=float)
    src_mac = (src_mac or "").lower()
    d = df[df["src"] == src_mac].copy()
    if d.empty:
        return pd.Series([], dtype=float)
    t0 = d["t"].min()
    d["sec"] = (d["t"] - t0).astype(int)
    return d.groupby("sec").size().astype(float)

def _series_matrix(series_list: List[pd.Series], window: int) -> np.ndarray:
    mats = []
    idx = pd.RangeIndex(0, window)
    for s in series_list:
        if s is None or len(s) == 0:
            mats.append(pd.Series(0.0, index=idx))
        else:
            mats.append(s.reindex(idx, fill_value=0.0))
    df = pd.concat(mats, axis=1).T
    return df.values.astype(float)

def _ci_band_per_timestep(mat: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    if mat.size == 0:
        return (np.array([]), np.array([]), np.array([]))
    k = mat.shape[0]
    mu = np.mean(mat, axis=0)
    if k <= 1:
        return (mu, mu, mu)
    s = np.std(mat, axis=0, ddof=1)
    se = s / math.sqrt(k)
    df = k - 1
    t = T975.get(df, 1.96)
    half = t * se
    return (mu, mu - half, mu + half)

def _discover_attack_dirs(args, runs_root: Path) -> List[Path]:
    """Resolve attack run directories.

    Supports two modes:
      1) One or more explicit directories via --attack_run_dir PATH (repeatable).
         If PATH does not exist, we also try resolving it under --runs_root.
      2) An enumerated range via --attack_prefix PREFIX --attack_start N --attack_end M.

    Returns a deduplicated list of existing run directories.
    """
    dirs: List[Path] = []

    # Explicit paths (repeatable)
    if getattr(args, "attack_run_dir", None):
        for p in args.attack_run_dir:
            if not p:
                continue
            d = Path(p)
            if not d.exists():
                # Common convenience: user passes 'combined_001' instead of 'runs/combined_001'
                d2 = runs_root / p
                if d2.exists():
                    d = d2
            dirs.append(d)

    # Enumerated by prefix under runs_root
    if getattr(args, "attack_prefix", "") and getattr(args, "attack_start", 0) and getattr(args, "attack_end", 0):
        for rid in run_ids(args.attack_prefix, args.attack_start, args.attack_end):
            dirs.append(runs_root / rid)

    out: List[Path] = []
    seen = set()
    for d in dirs:
        try:
            key = str(d.resolve())
        except Exception:
            key = str(d)
        if key in seen:
            continue
        if d.exists() and d.is_dir():
            out.append(d)
            seen.add(key)

    return out

# -------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("--runs_root", default="runs", help="Folder containing baseline_001..baseline_010, etc.")
    ap.add_argument("--baseline_prefix", default="baseline_", help="Run directory prefix for baseline.")
    ap.add_argument("--defense_prefix", default="defense_", help="Run directory prefix for defense.")
    ap.add_argument("--start", type=int, default=1, help="Start index, e.g., 1 for *_001.")
    ap.add_argument("--end", type=int, default=10, help="End index, e.g., 10 for *_010.")
    ap.add_argument("--hmi_iface", default="DPSRS-eth4", help="Interface name for HMI capture inside each run dir.")
    ap.add_argument("--uplink_iface", default="DPSRS-eth2", help="Interface name for uplink capture inside each run dir.")

    # Multi-attack support (repeatable explicit dirs OR prefix range)
    ap.add_argument("--attack_run_dir", action="append", default=[],
                    help="Attack run dir (repeatable). Each dir must contain attacker/hmi/uplink pcaps.")
    ap.add_argument("--attack_prefix", default="", help="Attack run directory prefix under --runs_root (e.g., combined_)")
    ap.add_argument("--attack_start", type=int, default=None, help="Attack start index (e.g., 1 for combined_001)")
    ap.add_argument("--attack_end", type=int, default=None, help="Attack end index (e.g., 5 for combined_005)")
    ap.add_argument("--attack_common_window_s", type=int, default=0,
                    help="Force a common window length (seconds) for attack time-series. 0=auto (min duration across runs).")
    ap.add_argument("--attack_per_run_plots", action="store_true",
                    help="Also emit per-attack-run fig2/fig3 for debugging (in addition to aggregated).")

    ap.add_argument("--attacker_iface", default="DPSRS-eth5")
    ap.add_argument("--attacker_mac", default="auto",
                    help='Attacker src MAC for Fig2/Fig3. Use "auto" to infer per-run from attacker interface capture.')
    ap.add_argument("--ovs_flows_post", default="")
    ap.add_argument("--cookie", default="0x99990001")

    ap.add_argument("--dedup_ms", type=float, default=0.0, help="Discard inter-arrival deltas < dedup_ms.")
    ap.add_argument("--outdir", default="figures")
    ap.add_argument("--export_envelopes_csv", default="", help="CSV path for per-run + summary stats + paired deltas.")
    args = ap.parse_args()

    runs_root = Path(args.runs_root)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    b_ids = run_ids(args.baseline_prefix, args.start, args.end)
    d_ids = run_ids(args.defense_prefix, args.start, args.end)

    baseline_runs = [(rid, runs_root / rid) for rid in b_ids if (runs_root / rid).exists()]
    defense_runs  = [(rid, runs_root / rid) for rid in d_ids if (runs_root / rid).exists()]

    if len(baseline_runs) == 0:
        raise SystemExit(f"No baseline run dirs found under {runs_root} with prefix {args.baseline_prefix}")
    if len(defense_runs) == 0:
        raise SystemExit(f"No defense run dirs found under {runs_root} with prefix {args.defense_prefix}")

    per_run_rows: List[dict] = []
    pooled_sv_b, pooled_sv_d = [], []
    pooled_lat_b, pooled_lat_d = [], []

    sv_rate_by_idx = {"baseline": {}, "defense": {}}

    for rid, rdir in baseline_runs:
        idx = parse_run_index(rid)
        m = compute_run_metrics(rdir, args.hmi_iface, args.uplink_iface, args.dedup_ms)

        per_run_rows += rows_from_envelopes("baseline", rid, "SV_interarrival_ms", m["sv_per"], m["sv_agg"])
        per_run_rows += rows_from_envelopes("baseline", rid, "GOOSE_interarrival_ms", m["goose_ia_per"], m["goose_ia_agg"])

        st_lat = summarize(m["goose_lat"]) or {"n": 0}
        per_run_rows.append({
            "value_type": "raw",
            "row_type": "per_run",
            "case": "baseline",
            "run": rid,
            "metric": "GOOSE_uplink_to_hmi_latency_ms",
            "scope": "aggregated",
            "publisher": "ALL",
            **st_lat,
        })

        per_run_rows.append(scalar_row("baseline", rid, "GOOSE_delivery_ratio", m["goose_dr"]))
        per_run_rows.append(scalar_row("baseline", rid, "SV_rate_pkts_per_sec", m["sv_rate"]))

        if idx is not None:
            sv_rate_by_idx["baseline"][idx] = m["sv_rate"]

        pooled_sv_b.append(m["sv_agg"])
        pooled_lat_b.append(m["goose_lat"])

    for rid, rdir in defense_runs:
        idx = parse_run_index(rid)
        m = compute_run_metrics(rdir, args.hmi_iface, args.uplink_iface, args.dedup_ms)

        per_run_rows += rows_from_envelopes("defense", rid, "SV_interarrival_ms", m["sv_per"], m["sv_agg"])
        per_run_rows += rows_from_envelopes("defense", rid, "GOOSE_interarrival_ms", m["goose_ia_per"], m["goose_ia_agg"])

        st_lat = summarize(m["goose_lat"]) or {"n": 0}
        per_run_rows.append({
            "value_type": "raw",
            "row_type": "per_run",
            "case": "defense",
            "run": rid,
            "metric": "GOOSE_uplink_to_hmi_latency_ms",
            "scope": "aggregated",
            "publisher": "ALL",
            **st_lat,
        })

        per_run_rows.append(scalar_row("defense", rid, "GOOSE_delivery_ratio", m["goose_dr"]))
        per_run_rows.append(scalar_row("defense", rid, "SV_rate_pkts_per_sec", m["sv_rate"]))

        if idx is not None:
            sv_rate_by_idx["defense"][idx] = m["sv_rate"]

        pooled_sv_d.append(m["sv_agg"])
        pooled_lat_d.append(m["goose_lat"])

    df_per_run = pd.DataFrame(per_run_rows)

    loss_rows = []
    paired_idx = sorted(set(sv_rate_by_idx["baseline"].keys()) & set(sv_rate_by_idx["defense"].keys()))
    for idx in paired_idx:
        rb = sv_rate_by_idx["baseline"][idx]
        rd = sv_rate_by_idx["defense"][idx]
        if rb and rb > 0 and not (math.isnan(rb) or math.isnan(rd)):
            lp = 1.0 - (rd / rb)
            loss_rows.append({
                "value_type": "raw",
                "row_type": "per_run",
                "case": "defense",
                "run": f"lossproxy_{idx:03d}",
                "metric": "SV_loss_proxy",
                "scope": "aggregated",
                "publisher": "ALL",
                "n": 1,
                "mean": lp,
            })
    if loss_rows:
        df_per_run = pd.concat([df_per_run, pd.DataFrame(loss_rows)], ignore_index=True, sort=False)

    pooled_sv_b = pd.concat([s for s in pooled_sv_b if not s.empty], ignore_index=True) if pooled_sv_b else pd.Series([], dtype=float)
    pooled_sv_d = pd.concat([s for s in pooled_sv_d if not s.empty], ignore_index=True) if pooled_sv_d else pd.Series([], dtype=float)
    pooled_lat_b = pd.concat([s for s in pooled_lat_b if not s.empty], ignore_index=True) if pooled_lat_b else pd.Series([], dtype=float)
    pooled_lat_d = pd.concat([s for s in pooled_lat_d if not s.empty], ignore_index=True) if pooled_lat_d else pd.Series([], dtype=float)

    summary_rows = []
    for case in ["baseline", "defense"]:
        for metric in ["SV_interarrival_ms", "GOOSE_interarrival_ms", "GOOSE_uplink_to_hmi_latency_ms",
                       "GOOSE_delivery_ratio", "SV_rate_pkts_per_sec"]:
            rec = summary_rows_from_perrun(df_per_run, case, metric, "aggregated", "ALL")
            if rec:
                summary_rows.append(rec)

        for metric in ["SV_interarrival_ms", "GOOSE_interarrival_ms"]:
            pubs = sorted(df_per_run[
                (df_per_run["value_type"] == "raw") &
                (df_per_run["row_type"] == "per_run") &
                (df_per_run["case"] == case) &
                (df_per_run["metric"] == metric) &
                (df_per_run["scope"] == "publisher")
            ]["publisher"].unique().tolist())
            for pub in pubs:
                rec = summary_rows_from_perrun(df_per_run, case, metric, "publisher", pub)
                if rec:
                    summary_rows.append(rec)

    rec_lp = summary_rows_from_perrun(df_per_run, "defense", "SV_loss_proxy", "aggregated", "ALL")
    if rec_lp:
        summary_rows.append(rec_lp)

    df_summary = pd.DataFrame(summary_rows)

    df_raw_for_delta = df_per_run[
        (df_per_run["value_type"] == "raw") &
        (df_per_run["row_type"] == "per_run") &
        (df_per_run["case"].isin(["baseline", "defense"]))
    ].copy()
    df_delta = paired_delta_rows(df_raw_for_delta, args.baseline_prefix, args.defense_prefix)

    fig1 = plt.figure(figsize=(10, 7))
    ax1 = fig1.add_subplot(2, 1, 1)
    xb, yb = ecdf(pooled_sv_b); xd, yd = ecdf(pooled_sv_d)
    ax1.plot(xb, yb, label="Baseline (pooled)")
    ax1.plot(xd, yd, label="Defense (pooled)")
    ax1.set_xlabel("SV inter-arrival (ms) [pooled across runs]")
    ax1.set_ylabel("ECDF")
    ax1.set_title("HMI SV timing ECDF (pooled across runs)")
    ax1.legend()

    ax2 = fig1.add_subplot(2, 1, 2)
    pooled_lat_b_us = np.array(pooled_lat_b, dtype=float) * 1000.0
    pooled_lat_d_us = np.array(pooled_lat_d, dtype=float) * 1000.0
    xb, yb = ecdf(pooled_lat_b_us); xd, yd = ecdf(pooled_lat_d_us)
    ax2.plot(xb, yb, label="Baseline (pooled)")
    ax2.plot(xd, yd, label="Defense (pooled)")
    ax2.set_xlabel("GOOSE uplink→HMI latency (µs) [pooled across runs]")
    ax2.set_ylabel("ECDF")
    ax2.set_title("GOOSE delivery & latency ECDF (matched by full-frame hash)")
    ax2.legend()

    fig1.tight_layout()
    fig1.savefig(outdir / "fig1_hmi_baseline_vs_defense.png", dpi=200)
    fig1.savefig(outdir / "fig1_hmi_baseline_vs_defense.pdf")
    plt.close(fig1)

    # --- Multi-attack aggregated figures ---
    attack_dirs = _discover_attack_dirs(args, runs_root)
    if (getattr(args, 'attack_run_dir', None) or getattr(args, 'attack_prefix', '')) and not attack_dirs:
        print('[warn] No attack run dirs found. If you passed a bare name like combined_001, either use --runs_root runs or pass --attack_run_dir runs/combined_001.')

    if attack_dirs:
        print(f"[*] Multi-attack: found {len(attack_dirs)} attack run dir(s).")
        s_att_list, s_hmi_list = [], []
        per_run_meta = []
        durations = []

        for atk_dir in attack_dirs:
            p_att = find_iface_pcap(atk_dir, args.attacker_iface)
            p_hmi = find_iface_pcap(atk_dir, args.hmi_iface)
            p_upl = find_iface_pcap(atk_dir, args.uplink_iface)

            df_att = read_pcap_df(p_att)
            df_hmi = read_pcap_df(p_hmi)
            df_upl = read_pcap_df(p_upl)

            if (not args.attacker_mac) or (str(args.attacker_mac).strip().lower() == "auto"):
                mac = _infer_attacker_mac(df_att)
            else:
                mac = str(args.attacker_mac).strip().lower()

            if not mac:
                print(f"[warn] {atk_dir}: could not infer attacker MAC; skipping.")
                continue

            s_att = _pps_series(df_att, mac)
            s_hmi = _pps_series(df_hmi, mac)
            if (not s_att.empty) and s_hmi.empty:
                s_hmi = pd.Series(0.0, index=s_att.index)

            if not s_att.empty:
                dur = int(s_att.index.max()) + 1
            elif not s_hmi.empty:
                dur = int(s_hmi.index.max()) + 1
            else:
                dur = 1
                s_att = pd.Series([0.0], index=[0])
                s_hmi = pd.Series([0.0], index=[0])

            durations.append(dur)
            s_att_list.append(s_att)
            s_hmi_list.append(s_hmi)

            atk_on_att = int((df_att["src"] == mac).sum())
            atk_on_upl = int((df_upl["src"] == mac).sum())
            atk_on_hmi = int((df_hmi["src"] == mac).sum())
            per_run_meta.append((atk_dir, mac, atk_on_att, atk_on_upl, atk_on_hmi))

            if args.attack_per_run_plots:
                fig2r = plt.figure(figsize=(10, 4))
                axr = fig2r.add_subplot(1, 1, 1)
                axr.plot(s_att.index, s_att.values, label="Attacker interface (sent)")
                axr.plot(s_hmi.index, s_hmi.values, label="HMI interface (received)")
                axr.set_xlabel("Time (s)")
                axr.set_ylabel("Packets/s (attacker-originated)")
                axr.set_title(f"Attacker vs HMI (run={atk_dir.name}, src={mac})")
                axr.legend()
                fig2r.tight_layout()
                fig2r.savefig(outdir / f"fig2_attacker_vs_hmi_{atk_dir.name}.png", dpi=200)
                fig2r.savefig(outdir / f"fig2_attacker_vs_hmi_{atk_dir.name}.pdf")
                plt.close(fig2r)

                fig3r = plt.figure(figsize=(9, 4))
                ax3r = fig3r.add_subplot(1, 1, 1)
                labels = ["Attacker link", "Uplink", "HMI link"]
                values = [atk_on_att, atk_on_upl, atk_on_hmi]
                ax3r.bar(labels, values)
                for i, val in enumerate(values):
                    ax3r.text(i, val, f"{int(val)}", ha="center", va="bottom", fontsize=9)
                if atk_on_att > 0:
                    pct_upl = 100.0 * (atk_on_upl / atk_on_att)
                    pct_hmi = 100.0 * (atk_on_hmi / atk_on_att)
                    ax3r.text(0.99, 0.98, f"Forwarded: uplink {pct_upl:.2f}% | HMI {pct_hmi:.2f}%",
                              transform=ax3r.transAxes, ha="right", va="top", fontsize=9)
                ax3r.set_ylabel("Packets (attacker-originated)")
                ax3r.set_title(f"Containment proof (run={atk_dir.name}, src={mac})")
                fig3r.tight_layout()
                fig3r.savefig(outdir / f"fig3_containment_{atk_dir.name}.png", dpi=200)
                fig3r.savefig(outdir / f"fig3_containment_{atk_dir.name}.pdf")
                plt.close(fig3r)
        if s_att_list:
            window = int(args.attack_common_window_s) if args.attack_common_window_s and args.attack_common_window_s > 0 else int(min(durations))
            window = max(window, 1)

            mat_att = _series_matrix(s_att_list, window)
            mat_hmi = _series_matrix(s_hmi_list, window)
            mu_att, lo_att, hi_att = _ci_band_per_timestep(mat_att)
            mu_hmi, lo_hmi, hi_hmi = _ci_band_per_timestep(mat_hmi)

            t = np.arange(window)

            fig2 = plt.figure(figsize=(10, 4))
            ax = fig2.add_subplot(1, 1, 1)
            ax.plot(t, mu_att, label=f"Attacker interface (sent) mean (k={mat_att.shape[0]})")
            ax.fill_between(t, lo_att, hi_att, alpha=0.2)
            ax.plot(t, mu_hmi, label=f"HMI interface (received) mean (k={mat_hmi.shape[0]})")
            ax.fill_between(t, lo_hmi, hi_hmi, alpha=0.2)
            ax.set_xlabel("Time (s)")
            ax.set_ylabel("Packets/s (attacker-originated)")
            ax.set_title("Attacker vs HMI: sent vs received (mean ± 95% CI across combined attacks)")
            ax.legend()
            fig2.tight_layout()

            # Always write the multi-attack filenames (paper-ready when k>1).
            fig2.savefig(outdir / "fig2_attacker_vs_hmi_multi.png", dpi=200)
            fig2.savefig(outdir / "fig2_attacker_vs_hmi_multi.pdf")

            # Backward-compatible names when k==1
            if len(attack_dirs) == 1:
                fig2.savefig(outdir / "fig2_attacker_vs_hmi.png", dpi=200)
                fig2.savefig(outdir / "fig2_attacker_vs_hmi.pdf")

            plt.close(fig2)
        else:
            print("[warn] Attack analysis: no attacker-originated frames found in the attack pcaps (s_att_list empty).")

        # FIG3: aggregate containment counts (works even if series are empty)
        total_att = int(sum(x[2] for x in per_run_meta))
        total_upl = int(sum(x[3] for x in per_run_meta))
        total_hmi = int(sum(x[4] for x in per_run_meta))

        fig3 = plt.figure(figsize=(9, 4))
        ax3 = fig3.add_subplot(1, 1, 1)
        labels = ["Attacker link", "Uplink", "HMI link"]
        values = [total_att, total_upl, total_hmi]
        ax3.bar(labels, values)
        for i, val in enumerate(values):
            ax3.text(i, val, f"{int(val)}", ha="center", va="bottom", fontsize=9)
        if total_att > 0:
            pct_upl = 100.0 * (total_upl / total_att)
            pct_hmi = 100.0 * (total_hmi / total_att)
            ax3.text(0.99, 0.98, f"Forwarded (aggregate): uplink {pct_upl:.2f}% | HMI {pct_hmi:.2f}%",
                     transform=ax3.transAxes, ha="right", va="top", fontsize=9)
        ax3.set_ylabel("Packets (attacker-originated)")
        ax3.set_title("Containment proof: attacker-originated traffic across combined attacks (aggregate)")
        fig3.tight_layout()

        fig3.savefig(outdir / "fig3_containment_uplink_vs_hmi_multi.png", dpi=200)
        fig3.savefig(outdir / "fig3_containment_uplink_vs_hmi_multi.pdf")
        if len(attack_dirs) == 1:
            fig3.savefig(outdir / "fig3_containment_uplink_vs_hmi.png", dpi=200)
            fig3.savefig(outdir / "fig3_containment_uplink_vs_hmi.pdf")
        plt.close(fig3)

    if args.export_envelopes_csv:

        out_csv = Path(args.export_envelopes_csv)
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        df_all = pd.concat([df_per_run, df_summary, df_delta], ignore_index=True, sort=False)
        df_all.to_csv(out_csv, index=False)
        print(f"[*] Exported envelopes CSV (incl. deltas): {out_csv}")

    print(f"[*] Wrote figures to: {outdir}")

if __name__ == "__main__":
    main()
