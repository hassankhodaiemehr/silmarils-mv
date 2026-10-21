"""Permissioned-ledger workload model for signature-scheme comparison."""

from __future__ import annotations

import time
from dataclasses import dataclass

from pqc_catalog import SignatureScheme, VerifierModel
from silmarils_core import Silmarils


@dataclass(frozen=True)
class LedgerConfig:
    validators: int = 7
    tx_per_block: int = 500
    blocks_per_minute: float = 2.0
    consensus_rounds_per_block: int = 3
    user_tx_ratio: float = 0.85


@dataclass
class WorkloadMetrics:
    scheme: str
    verifier_model: str
    tx_auth_bytes: int
    consensus_auth_bytes: int
    total_auth_bytes_per_block: int
    total_auth_mib_per_minute: float
    est_sign_cpu_ms_per_block: float
    est_verify_cpu_ms_per_block: float
    notes: str


def _consensus_messages(config: LedgerConfig) -> int:
    # Each validator attests to each peer during BFT-style rounds.
    return config.validators * (config.validators - 1) * config.consensus_rounds_per_block


def measure_silmarils_runtime(samples: int = 200) -> tuple[float, float]:
    scheme = Silmarils()
    keys = scheme.keygen()
    message = b"demo transaction payload"

    sign_start = time.perf_counter()
    for _ in range(samples):
        sig = scheme.sign(message, keys)
        _ = scheme.verify(message, sig, keys)
    elapsed = time.perf_counter() - sign_start

    per_op_us = (elapsed / (2 * samples)) * 1_000_000
    return per_op_us, per_op_us


def evaluate_scheme(scheme: SignatureScheme, config: LedgerConfig) -> WorkloadMetrics:
    user_txs = int(config.tx_per_block * config.user_tx_ratio)
    consensus_msgs = _consensus_messages(config)

    tx_auth = user_txs * scheme.sig_bytes
    consensus_auth = consensus_msgs * scheme.sig_bytes
    total_auth = tx_auth + consensus_auth

    sign_us = scheme.sign_us
    verify_us = scheme.verify_us
    if scheme.is_silmarils:
        sign_us, verify_us = measure_silmarils_runtime()

    sign_ops = user_txs + consensus_msgs
    verify_ops = user_txs + consensus_msgs * (config.validators - 1)

    sign_ms = (sign_ops * (sign_us or 0.0)) / 1000.0
    verify_ms = (verify_ops * (verify_us or 0.0)) / 1000.0

    per_minute_blocks = config.blocks_per_minute
    auth_mib_per_minute = (total_auth * per_minute_blocks) / (1024 * 1024)

    if scheme.verifier == VerifierModel.TDV:
        notes = (
            "TDV ledger profile: validators verify with k_sig; auditors use "
            "AuditVerify on published (M,sigma,r) without secrets."
        )
    else:
        notes = "Public verifier: any party can check signatures; larger on-chain footprint."

    return WorkloadMetrics(
        scheme=scheme.name,
        verifier_model=scheme.verifier.value,
        tx_auth_bytes=tx_auth,
        consensus_auth_bytes=consensus_auth,
        total_auth_bytes_per_block=total_auth,
        total_auth_mib_per_minute=auth_mib_per_minute,
        est_sign_cpu_ms_per_block=sign_ms,
        est_verify_cpu_ms_per_block=verify_ms,
        notes=notes,
    )


def hybrid_stack_summary() -> str:
    return (
        "Hybrid deployment (recommended in the SILMARILS blockchain narrative):\n"
        "  • Transport layer: TLS 1.3 derives pairwise k_sig for SILMARILS sessions\n"
        "  • Hot path (consensus + user auth): SILMARILS TDV receipts\n"
        "  • Governance / bridges / public audit anchors: ML-DSA or SLH-DSA\n"
    )
