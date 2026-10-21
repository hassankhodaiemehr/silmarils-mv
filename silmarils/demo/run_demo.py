#!/usr/bin/env python3
"""SILMARILS blockchain demo: live crypto + PQC comparison."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from blockchain_sim import LedgerConfig, evaluate_scheme, hybrid_stack_summary
from pqc_catalog import SCHEMES, primary_comparison
from silmarils_core import Silmarils


def _fmt_bytes(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.2f} MiB"
    if n >= 1024:
        return f"{n / 1024:.1f} KiB"
    return f"{n} B"


def run_live_flow() -> None:
    print("=" * 72)
    print("LIVE SILMARILS FLOW — permissioned ledger transaction")
    print("=" * 72)

    scheme = Silmarils()
    keys = scheme.keygen()

    actors = {
        "P1 (signer / user)": "Submits transfer to mempool",
        "P2 (holder / mempool)": "Buffers transaction, forwards to validator",
        "P3 (validator / DV)": "Verifies TDV signature, includes in block",
    }
    for role, action in actors.items():
        print(f"  {role}: {action}")

    message = b'{"from":"alice","to":"bob","amount":100,"nonce":42}'
    print(f"\nMessage: {message.decode()}")

    signature = scheme.sign(message, keys)
    ok = scheme.verify(message, signature, keys)
    simulated = scheme.simulate(message, keys)
    sim_ok = scheme.verify(message, simulated, keys)

    print(f"\n  Real signature verify:       {'PASS' if ok else 'FAIL'}")
    print(f"  Simulated (DV) verify:         {'PASS' if sim_ok else 'FAIL'}")
    print(f"  Public audit verify:           {'PASS' if scheme.audit_verify(message, signature) else 'FAIL'}")
    print(f"  Signature size:                {signature.byte_size} bytes")
    print(f"  Ledger transcript (σ+r):       {signature.ledger_transcript_bytes} bytes")
    print(f"  Signer identity I=H(K):        {keys.identity}")
    print(
        "\n  Note: only the designated verifier can distinguish real vs simulated "
        "transcripts — this is intentional TDV semantics, not a bug."
    )


def print_size_table() -> None:
    print("\n" + "=" * 72)
    print("SIGNATURE SIZE COMPARISON (256-bit / NIST L1–L2 level)")
    print("=" * 72)
    print(f"{'Scheme':<28} {'Sig (B)':>8} {'PK (B)':>8} {'Verifier':<22}")
    print("-" * 72)

    dilithium2_sig = next(s.sig_bytes for s in SCHEMES if "Dilithium-2" in s.name)
    for scheme in primary_comparison():
        ratio = (scheme.sig_bytes / dilithium2_sig) * 100
        marker = " <-- TDV" if scheme.is_silmarils else ""
        print(
            f"{scheme.name:<28} {scheme.sig_bytes:>8} {scheme.pk_bytes:>8} "
            f"{scheme.verifier.value[:20]:<22}{marker}"
        )
        if not scheme.is_silmarils:
            print(f"{'':28} ({ratio:5.1f}% of Dilithium-2 sig size)")

    print(
        "\n  Fair comparison caveat: SILMARILS is NOT a drop-in Dilithium replacement."
        "\n  Sizes reflect efficiency where designated verification suffices."
    )


def print_ledger_metrics(config: LedgerConfig) -> None:
    print("\n" + "=" * 72)
    print("PERMISSIONED LEDGER WORKLOAD MODEL")
    print("=" * 72)
    print(
        f"  Validators: {config.validators} | Txs/block: {config.tx_per_block} | "
        f"Blocks/min: {config.blocks_per_minute} | "
        f"Consensus rounds/block: {config.consensus_rounds_per_block}"
    )
    print(f"\n{'Scheme':<28} {'Auth/block':>12} {'Auth/min':>12} {'Verify CPU':>12}")
    print("-" * 72)

    results = []
    for scheme in primary_comparison():
        m = evaluate_scheme(scheme, config)
        results.append(m)
        print(
            f"{m.scheme:<28} {_fmt_bytes(m.total_auth_bytes_per_block):>12} "
            f"{m.total_auth_mib_per_minute:>9.2f} MiB "
            f"{m.est_verify_cpu_ms_per_block:>9.1f} ms"
        )

    sil = next(r for r in results if r.scheme == "SILMARILS")
    dil = next(r for r in results if "Dilithium-2" in r.scheme)
    savings = (1 - sil.total_auth_bytes_per_block / dil.total_auth_bytes_per_block) * 100
    print(
        f"\n  SILMARILS reduces per-block auth payload by ~{savings:.0f}% vs Dilithium-2 "
        f"in this model ({_fmt_bytes(dil.total_auth_bytes_per_block)} -> "
        f"{_fmt_bytes(sil.total_auth_bytes_per_block)})."
    )


def save_charts(output_dir: Path) -> None:
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n  Skipping charts (install matplotlib: pip install -r requirements.txt)")
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    schemes = primary_comparison()
    names = [s.name.replace(" (ML-DSA-44)", "") for s in schemes]
    sig_sizes = [s.sig_bytes for s in schemes]
    colors = ["#005785" if s.is_silmarils else "#dc5a46" for s in schemes]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(names, sig_sizes, color=colors, edgecolor="white", linewidth=0.8)
    ax.set_ylabel("Signature size (bytes)")
    ax.set_title("SILMARILS vs NIST PQC — signature sizes at ~128-bit security")
    ax.set_yscale("log")
    ax.grid(axis="y", alpha=0.3, linestyle="--")

    for bar, size in zip(bars, sig_sizes):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 1.08,
            f"{size:,}",
            ha="center",
            va="bottom",
            fontsize=9,
        )

    fig.text(
        0.5,
        0.01,
        "SILMARILS is TDV (designated verifier), not publicly verifiable like ML-DSA/SLH-DSA.",
        ha="center",
        fontsize=8,
        color="#555555",
    )
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    chart1 = output_dir / "signature_sizes.png"
    fig.savefig(chart1, dpi=150)
    plt.close(fig)

    config = LedgerConfig()
    metrics = [evaluate_scheme(s, config) for s in schemes]
    auth_per_block = [m.total_auth_bytes_per_block for m in metrics]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(names, auth_per_block, color=colors, edgecolor="white", linewidth=0.8)
    ax.set_ylabel("Authentication bytes per block")
    ax.set_title(
        f"Permissioned ledger auth overhead "
        f"({config.validators} validators, {config.tx_per_block} txs/block)"
    )
    ax.grid(axis="y", alpha=0.3, linestyle="--")

    for bar, size in zip(bars, auth_per_block):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() * 1.02,
            _fmt_bytes(size),
            ha="center",
            va="bottom",
            fontsize=9,
        )

    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    chart2 = output_dir / "ledger_auth_overhead.png"
    fig.savefig(chart2, dpi=150)
    plt.close(fig)

    print(f"\n  Charts saved to:\n    {chart1}\n    {chart2}")


def export_json(output_path: Path, config: LedgerConfig) -> None:
    payload = {
        "ledger_config": config.__dict__,
        "schemes": [
            {
                **s.__dict__,
                "verifier": s.verifier.value,
                "workload": evaluate_scheme(s, config).__dict__,
            }
            for s in primary_comparison()
        ],
        "hybrid_deployment": hybrid_stack_summary(),
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\n  JSON report: {output_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SILMARILS blockchain demo with PQC comparison"
    )
    parser.add_argument(
        "--charts",
        action="store_true",
        help="Generate comparison charts (requires matplotlib)",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Export metrics to JSON file",
    )
    parser.add_argument(
        "--validators",
        type=int,
        default=7,
        help="Number of validators in workload model",
    )
    parser.add_argument(
        "--tx-per-block",
        type=int,
        default=500,
        help="Transactions per block",
    )
    args = parser.parse_args()

    config = LedgerConfig(validators=args.validators, tx_per_block=args.tx_per_block)

    run_live_flow()
    print_size_table()
    print_ledger_metrics(config)
    print("\n" + hybrid_stack_summary())

    out_dir = Path(__file__).resolve().parent / "output"
    if args.charts:
        save_charts(out_dir)
    if args.json:
        export_json(args.json, config)
    elif args.charts:
        export_json(out_dir / "comparison_report.json", config)

    return 0


if __name__ == "__main__":
    sys.exit(main())
