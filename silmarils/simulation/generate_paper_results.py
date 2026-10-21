#!/usr/bin/env python3
"""Generate paper-aligned simulation results and LaTeX figure coordinates."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from constants import (  # noqa: E402
    DEFAULT_BASE_TPS,
    DEFAULT_BLOCK_AUTH_CAP_BYTES,
    DEFAULT_NETWORK_MBPS,
    DEFAULT_VALIDATORS,
    DILITHIUM2_SIG_BYTES,
    FIELD_BYTES,
    FULL_PQ_RETROFIT_TPS_LOSS_PCT,
    HYBRID_TPS_LOSS_PCT,
    LEDGER_FIELD_BYTES,
    PK_BYTES,
    PQ_SIG_BYTES,
    PQ_WORKLOAD_MACROS,
    SIG_ALG_BYTES,
    SK_BYTES,
    LedgerConfig,
)
from three_party_relay import IC_SIZES, evaluate_three_party_relay, relay_bandwidth_curve  # noqa: E402
from pq_benchmarks import HardwareBenchmarkError, timing_source_summary  # noqa: E402
from two_party_ledger import (  # noqa: E402
    PQ_TIMINGS,
    PQ_TIMING_META,
    evaluate_tps,
    evaluate_two_party,
    measure_silmarils_us,
)

OUTPUT_DIR = ROOT / "output"
VALIDATOR_GRID = [3, 5, 7, 9, 11, 15, 21]


def _fmt_coord_pairs(pairs: list[tuple[str, int]]) -> str:
    return " ".join(f"({a},{b})" for a, b in pairs)


def _fmt_log10_coord_pairs(pairs: list[tuple[str, float]]) -> str:
    """log10(KiB) coordinates for MATLAB-style semilogy (linear axis in log-space)."""
    return " ".join(f"({a},{math.log10(b):.6f})" for a, b in pairs)


def main() -> None:
    try:
        timing_source_summary()
    except HardwareBenchmarkError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    config = LedgerConfig()
    sil_timing = measure_silmarils_us()

    sil_two = evaluate_two_party(config, timing=sil_timing)
    dil_two = evaluate_two_party(config, sig_bytes=DILITHIUM2_SIG_BYTES, timing=PQ_TIMINGS["Dilithium-2"])
    fal_two = evaluate_two_party(config, sig_bytes=690, timing=PQ_TIMINGS["Falcon-512"])
    sf_two = evaluate_two_party(config, sig_bytes=17088, timing=PQ_TIMINGS["SPHINCS+-128f"])
    ss_two = evaluate_two_party(config, sig_bytes=7856, timing=PQ_TIMINGS["SPHINCS+-128s"])

    sil_tps = evaluate_tps(
        config, sil_two, sil_timing, DEFAULT_BASE_TPS,
        DEFAULT_BLOCK_AUTH_CAP_BYTES, DEFAULT_NETWORK_MBPS, "SILMARILS",
    )
    hyb_tps = evaluate_tps(
        config, sil_two, sil_timing, DEFAULT_BASE_TPS,
        DEFAULT_BLOCK_AUTH_CAP_BYTES, DEFAULT_NETWORK_MBPS, "Hybrid",
        hybrid_cpu_loss=HYBRID_TPS_LOSS_PCT,
    )
    dil_tps = evaluate_tps(
        config, dil_two, PQ_TIMINGS["Dilithium-2"], DEFAULT_BASE_TPS,
        DEFAULT_BLOCK_AUTH_CAP_BYTES, DEFAULT_NETWORK_MBPS, "Dilithium-2",
    )
    fal_tps = evaluate_tps(
        config, fal_two, PQ_TIMINGS["Falcon-512"], DEFAULT_BASE_TPS,
        DEFAULT_BLOCK_AUTH_CAP_BYTES, DEFAULT_NETWORK_MBPS, "Falcon-512",
    )
    sf_tps = evaluate_tps(
        config, sf_two, PQ_TIMINGS["SPHINCS+-128f"], DEFAULT_BASE_TPS,
        DEFAULT_BLOCK_AUTH_CAP_BYTES, DEFAULT_NETWORK_MBPS, "SPHINCS+-128f",
    )
    ss_tps = evaluate_tps(
        config, ss_two, PQ_TIMINGS["SPHINCS+-128s"], DEFAULT_BASE_TPS,
        DEFAULT_BLOCK_AUTH_CAP_BYTES, DEFAULT_NETWORK_MBPS, "SPHINCS+-128s",
    )
    pq_retrofit_tps = max(1, round(DEFAULT_BASE_TPS * (1 - FULL_PQ_RETROFIT_TPS_LOSS_PCT / 100)))

    relay_full = evaluate_three_party_relay(config, relay_ratio=1.0, timing=sil_timing)
    relay_half = evaluate_three_party_relay(config, relay_ratio=0.5, timing=sil_timing)

    def _relay_dict(r) -> dict:
        d = {k: v for k, v in r.__dict__.items() if k != "ic_sizes"}
        d["ic_sizes"] = {
            "p1_to_p2_bytes": r.ic_sizes.p1_to_p2_fields * FIELD_BYTES,
            "p1_to_p3_bytes": r.ic_sizes.p1_to_p3_fields * FIELD_BYTES,
            "broadcast_bytes": r.ic_sizes.broadcast_fields * FIELD_BYTES,
            "transfer_bytes": r.ic_sizes.transfer_bytes,
            "wire_bytes_per_relayed_tx": r.ic_sizes.wire_bytes_honest_path,
        }
        return d

    workload_curve = []
    pq_workload_curves: dict[str, list[dict]] = {}
    for v in VALIDATOR_GRID:
        cfg = LedgerConfig(validators=v)
        s = evaluate_two_party(cfg)
        row = {"validators": v, "sil_kib": round(s.auth_kib_per_block, 1)}
        for name, sig_bytes in PQ_SIG_BYTES.items():
            w = evaluate_two_party(cfg, sig_bytes=sig_bytes)
            key = f"pq_{PQ_WORKLOAD_MACROS[name].lower()}_kib"
            row[key] = round(w.auth_kib_per_block, 1)
        workload_curve.append(row)

    for name in PQ_SIG_BYTES:
        macro = PQ_WORKLOAD_MACROS[name]
        pq_workload_curves[name] = [
            {"validators": p["validators"], "kib": p[f"pq_{macro.lower()}_kib"]}
            for p in workload_curve
        ]

    relay_curve_full = relay_bandwidth_curve(config, VALIDATOR_GRID, relay_ratio=1.0)
    relay_curve_half = relay_bandwidth_curve(config, VALIDATOR_GRID, relay_ratio=0.5)

    ratio = DILITHIUM2_SIG_BYTES / SIG_ALG_BYTES

    pq_timing_rows = {
        name: {
            "sign_us": PQ_TIMINGS[name].sign_us,
            "verify_us": PQ_TIMINGS[name].verify_us,
            "source": PQ_TIMING_META[name].source,
            "platform": PQ_TIMING_META[name].platform,
        }
        for name in PQ_TIMINGS
    }

    results = {
        "paper": "IACR CIC SILMARILS",
        "artifacts": {
            "sk_bytes": SK_BYTES,
            "pk_bytes": PK_BYTES,
            "sigma_alg_bytes": SIG_ALG_BYTES,
            "receipt_bytes": FIELD_BYTES,
            "ledger_field_bytes": LEDGER_FIELD_BYTES,
        },
        "ledger_config": {
            "validators": config.validators,
            "tx_per_block": config.tx_per_block,
            "blocks_per_minute": config.blocks_per_minute,
            "consensus_rounds_per_block": config.consensus_rounds_per_block,
            "user_tx_ratio": config.user_tx_ratio,
        },
        "pq_timing_source": timing_source_summary(),
        "pq_timings_us": pq_timing_rows,
        "two_party": {
            "silmarils": sil_two.__dict__,
            "dilithium2": dil_two.__dict__,
            "size_ratio": round(ratio, 2),
            "sil_timing_us": {"sign": sil_timing.sign_us, "verify": sil_timing.verify_us},
        },
        "tps": {
            "base_tps": DEFAULT_BASE_TPS,
            "hybrid": hyb_tps.__dict__,
            "silmarils": sil_tps.__dict__,
            "dilithium2": dil_tps.__dict__,
            "falcon512": fal_tps.__dict__,
            "sphincs128f": sf_tps.__dict__,
            "sphincs128s": ss_tps.__dict__,
            "full_pq_retrofit": pq_retrofit_tps,
        },
        "three_party_ic": {
            "message_sizes": {
                "p1_to_p2_bytes": IC_SIZES.p1_to_p2_fields * FIELD_BYTES,
                "p1_to_p3_bytes": IC_SIZES.p1_to_p3_fields * FIELD_BYTES,
                "broadcast_bytes": IC_SIZES.broadcast_fields * FIELD_BYTES,
                "transfer_bytes": IC_SIZES.transfer_bytes,
                "wire_bytes_per_relayed_tx": IC_SIZES.wire_bytes_honest_path,
            },
            "relay_ratio_1.0": _relay_dict(relay_full),
            "relay_ratio_0.5": _relay_dict(relay_half),
        },
        "workload_curve": workload_curve,
        "pq_workload_curves": {
            name: curves for name, curves in pq_workload_curves.items()
        },
        "relay_curve_full": [
            {"v": v, "two_party_kib": round(a, 1), "three_party_kib": round(b, 1)}
            for v, a, b in relay_curve_full
        ],
        "relay_curve_half": [
            {"v": v, "two_party_kib": round(a, 1), "three_party_kib": round(b, 1)}
            for v, a, b in relay_curve_half
        ],
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    json_path = OUTPUT_DIR / "paper_results.json"
    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    sil_workload_coords = " ".join(
        f"({p['validators']},{p['sil_kib']})" for p in workload_curve
    )
    sil_workload_log = _fmt_log10_coord_pairs(
        [(str(p["validators"]), p["sil_kib"]) for p in workload_curve]
    )
    pq_workload_tex = ""
    pq_workload_log_tex = ""
    for name, macro in PQ_WORKLOAD_MACROS.items():
        coords = " ".join(
            f"({p['validators']},{p[f'pq_{macro.lower()}_kib']})" for p in workload_curve
        )
        log_coords = _fmt_log10_coord_pairs(
            [
                (str(p["validators"]), p[f"pq_{macro.lower()}_kib"])
                for p in workload_curve
            ]
        )
        pq_workload_tex += f"\\providecommand{{\\Sim{macro}Workload}}{{{coords}}}\n"
        pq_workload_log_tex += f"\\providecommand{{\\Sim{macro}WorkloadLog}}{{{log_coords}}}\n"

    relay_full_coords = " ".join(
        f"({v},{round(b, 1)})" for v, _, b in relay_curve_full
    )
    relay_half_coords = " ".join(
        f"({v},{round(b, 1)})" for v, _, b in relay_curve_half
    )
    relay_full_log = _fmt_log10_coord_pairs(
        [(str(v), b) for v, _, b in relay_curve_full]
    )
    relay_half_log = _fmt_log10_coord_pairs(
        [(str(v), b) for v, _, b in relay_curve_half]
    )

    tex = f"""% Generated by generate_paper_results.py — do not edit by hand.
\\providecommand{{\\SimSilWorkload}}{{{sil_workload_coords}}}
\\providecommand{{\\SimSilWorkloadLog}}{{{sil_workload_log}}}
{pq_workload_tex}{pq_workload_log_tex}\\providecommand{{\\SimRelayFullWorkload}}{{{relay_full_coords}}}
\\providecommand{{\\SimRelayFullWorkloadLog}}{{{relay_full_log}}}
\\providecommand{{\\SimRelayHalfWorkload}}{{{relay_half_coords}}}
\\providecommand{{\\SimRelayHalfWorkloadLog}}{{{relay_half_log}}}

\\providecommand{{\\SimTpsCpuHyb}}{{{hyb_tps.cpu_tps}}}
\\providecommand{{\\SimTpsBwHyb}}{{{hyb_tps.bandwidth_tps}}}
\\providecommand{{\\SimTpsCombHyb}}{{{hyb_tps.combined_tps}}}

\\providecommand{{\\SimTpsCpuSil}}{{{sil_tps.cpu_tps}}}
\\providecommand{{\\SimTpsBwSil}}{{{sil_tps.bandwidth_tps}}}
\\providecommand{{\\SimTpsCombSil}}{{{sil_tps.combined_tps}}}

\\providecommand{{\\SimTpsCpuDil}}{{{dil_tps.cpu_tps}}}
\\providecommand{{\\SimTpsBwDil}}{{{dil_tps.bandwidth_tps}}}
\\providecommand{{\\SimTpsCombDil}}{{{dil_tps.combined_tps}}}

\\providecommand{{\\SimTpsCpuSf}}{{{sf_tps.cpu_tps}}}
\\providecommand{{\\SimTpsBwSf}}{{{sf_tps.bandwidth_tps}}}
\\providecommand{{\\SimTpsCombSf}}{{{sf_tps.combined_tps}}}

\\providecommand{{\\SimTpsCpuSs}}{{{ss_tps.cpu_tps}}}
\\providecommand{{\\SimTpsBwSs}}{{{ss_tps.bandwidth_tps}}}
\\providecommand{{\\SimTpsCombSs}}{{{ss_tps.combined_tps}}}

\\providecommand{{\\SimTpsCpuFal}}{{{fal_tps.cpu_tps}}}
\\providecommand{{\\SimTpsBwFal}}{{{fal_tps.bandwidth_tps}}}
\\providecommand{{\\SimTpsCombFal}}{{{fal_tps.combined_tps}}}

\\providecommand{{\\SimTpsCombPq}}{{{pq_retrofit_tps}}}

\\providecommand{{\\SimSilBytesBlock}}{{{sil_two.total_auth_bytes_per_block}}}
\\providecommand{{\\SimDilBytesBlock}}{{{dil_two.total_auth_bytes_per_block}}}
\\providecommand{{\\SimSizeRatio}}{{{ratio:.1f}}}
\\providecommand{{\\SimRelayBytesTx}}{{{IC_SIZES.wire_bytes_honest_path}}}
\\providecommand{{\\SimRelayOverheadPct}}{{{relay_full.overhead_vs_two_party_pct:.1f}}}
\\providecommand{{\\SimRelayHalfKibBlock}}{{{relay_half.mixed_auth_kib_per_block:.1f}}}
\\providecommand{{\\SimRelayFullKibBlock}}{{{relay_full.mixed_auth_kib_per_block:.1f}}}
"""
    tex_path = OUTPUT_DIR / "figure_coordinates.tex"
    tex_path.write_text(tex, encoding="utf-8")

    print(f"Wrote {json_path}")
    print(f"Wrote {tex_path}")
    print(f"SILMARILS timing: sign={sil_timing.sign_us:.1f}us verify={sil_timing.verify_us:.1f}us")
    print(f"PQ timing source: {timing_source_summary()}")
    for name, row in pq_timing_rows.items():
        print(f"  {name}: sign={row['sign_us']:.1f}us verify={row['verify_us']:.1f}us ({row['source']})")
    print(f"Two-party v=7: SIL {sil_two.total_auth_bytes_per_block} B, Dil {dil_two.total_auth_bytes_per_block} B")
    print(f"Three-party relay (100%): {relay_full.relay_auth_bytes_per_tx} B/tx, block {relay_full.mixed_total_auth_bytes_per_block} B")
    print(f"TPS combined: SIL={sil_tps.combined_tps}, Dil={dil_tps.combined_tps}, Hyb={hyb_tps.combined_tps}")


if __name__ == "__main__":
    main()
