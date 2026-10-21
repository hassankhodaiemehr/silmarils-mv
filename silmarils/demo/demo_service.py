"""Shared demo logic for CLI and web API."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any

from blockchain_sim import LedgerConfig, evaluate_scheme, hybrid_stack_summary
from pqc_catalog import SCHEMES, primary_comparison
from silmarils_core import Silmarils


def fmt_bytes(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.2f} MiB"
    if n >= 1024:
        return f"{n / 1024:.1f} KiB"
    return f"{n} B"


@dataclass
class LiveFlowResult:
    message: str
    real_verify: bool
    simulated_verify: bool
    audit_verify: bool
    signature_bytes: int
    ledger_transcript_bytes: int
    signer_identity: str
    receipt: str
    sign_us: float
    verify_us: float


@dataclass
class ComparisonPayload:
    ledger_config: dict[str, Any]
    schemes: list[dict[str, Any]]
    hybrid_deployment: str
    highlights: dict[str, Any]


def run_live_flow(message: str | None = None) -> LiveFlowResult:
    payload = message or '{"from":"alice","to":"bob","amount":100,"nonce":42}'
    raw = payload.encode("utf-8")

    scheme = Silmarils()
    keys = scheme.keygen()

    t0 = time.perf_counter()
    real = scheme.sign(raw, keys)
    sign_us = (time.perf_counter() - t0) * 1_000_000

    t1 = time.perf_counter()
    real_ok = scheme.verify(raw, real, keys)
    verify_us = (time.perf_counter() - t1) * 1_000_000

    simulated = scheme.simulate(raw, keys)
    sim_ok = scheme.verify(raw, simulated, keys)
    audit_ok = scheme.audit_verify(raw, real)

    return LiveFlowResult(
        message=payload,
        real_verify=real_ok,
        simulated_verify=sim_ok,
        audit_verify=audit_ok,
        signature_bytes=real.byte_size,
        ledger_transcript_bytes=real.ledger_transcript_bytes,
        signer_identity=str(keys.identity),
        receipt=str(real.receipt),
        sign_us=round(sign_us, 2),
        verify_us=round(verify_us, 2),
    )


def build_comparison(
    validators: int = 7,
    tx_per_block: int = 500,
    blocks_per_minute: float = 2.0,
    consensus_rounds_per_block: int = 3,
) -> ComparisonPayload:
    config = LedgerConfig(
        validators=validators,
        tx_per_block=tx_per_block,
        blocks_per_minute=blocks_per_minute,
        consensus_rounds_per_block=consensus_rounds_per_block,
    )

    schemes_out: list[dict[str, Any]] = []
    for scheme in primary_comparison():
        workload = evaluate_scheme(scheme, config)
        dilithium2 = next(s for s in primary_comparison() if "Dilithium-2" in s.name)
        schemes_out.append(
            {
                "name": scheme.name,
                "short_name": scheme.name.split(" (")[0],
                "security_type": scheme.security_type,
                "pk_bytes": scheme.pk_bytes,
                "sk_bytes": scheme.sk_bytes,
                "sig_bytes": scheme.sig_bytes,
                "verifier": scheme.verifier.value,
                "assumptions": scheme.assumptions,
                "is_silmarils": scheme.is_silmarils,
                "is_public_verifier": scheme.verifier.value.startswith("Public"),
                "sig_ratio_vs_dilithium2_pct": round(
                    100 * scheme.sig_bytes / dilithium2.sig_bytes, 1
                ),
                "workload": asdict(workload),
            }
        )

    sil = next(s for s in schemes_out if s["is_silmarils"])
    dil = next(s for s in schemes_out if "Dilithium-2" in s["name"])
    savings_pct = round(
        100
        * (
            1
            - sil["workload"]["total_auth_bytes_per_block"]
            / dil["workload"]["total_auth_bytes_per_block"]
        ),
        1,
    )

    return ComparisonPayload(
        ledger_config=asdict(config),
        schemes=schemes_out,
        hybrid_deployment=hybrid_stack_summary(),
        highlights={
            "silmarils_sig_bytes": sil["sig_bytes"],
            "dilithium2_sig_bytes": dil["sig_bytes"],
            "size_reduction_factor": round(dil["sig_bytes"] / sil["sig_bytes"], 1),
            "auth_savings_pct_vs_dilithium2": savings_pct,
            "silmarils_auth_per_block": fmt_bytes(
                sil["workload"]["total_auth_bytes_per_block"]
            ),
            "dilithium2_auth_per_block": fmt_bytes(
                dil["workload"]["total_auth_bytes_per_block"]
            ),
        },
    )


def catalog_schemes() -> list[dict[str, Any]]:
    return [
        {
            "name": s.name,
            "security_type": s.security_type,
            "pk_bytes": s.pk_bytes,
            "sk_bytes": s.sk_bytes,
            "sig_bytes": s.sig_bytes,
            "verifier": s.verifier.value,
            "assumptions": s.assumptions,
            "is_silmarils": s.is_silmarils,
        }
        for s in SCHEMES
    ]
