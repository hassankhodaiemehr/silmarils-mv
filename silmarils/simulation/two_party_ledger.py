"""Two-party permissioned-ledger workload model (Section 9, direct signer-to-validator)."""

from __future__ import annotations

import time
from dataclasses import dataclass

from constants import SIG_ALG_BYTES, LedgerConfig
from pq_benchmarks import resolve_pq_timings
from silmarils_core import Silmarils


@dataclass(frozen=True)
class SchemeTiming:
    sign_us: float
    verify_us: float


@dataclass
class WorkloadResult:
    mode: str
    sig_bytes_per_auth: int
    tx_auth_bytes: int
    consensus_auth_bytes: int
    total_auth_bytes_per_block: int
    auth_kib_per_block: float
    auth_mib_per_minute: float
    est_sign_cpu_ms_per_block: float
    est_verify_cpu_ms_per_block: float


# PQ CPU latencies: author hardware JSON only (pq_benchmarks.py).
_PQ_RESOLVED = resolve_pq_timings(
    {"Dilithium-2", "Falcon-512", "SPHINCS+-128f", "SPHINCS+-128s"}
)
PQ_TIMINGS = {
    name: SchemeTiming(t.sign_us, t.verify_us) for name, t in _PQ_RESOLVED.items()
}
PQ_TIMING_META = {name: t for name, t in _PQ_RESOLVED.items()}


def measure_silmarils_us(samples: int = 200) -> SchemeTiming:
    scheme = Silmarils()
    keys = scheme.keygen()
    message = b"permissioned-ledger transaction payload"

    start = time.perf_counter()
    for _ in range(samples):
        sig = scheme.sign(message, keys)
        _ = scheme.verify(message, sig, keys)
    elapsed = time.perf_counter() - start
    per_op_us = (elapsed / (2 * samples)) * 1_000_000
    return SchemeTiming(per_op_us, per_op_us)


def _cpu_ms(
    config: LedgerConfig,
    sign_us: float,
    verify_us: float,
) -> tuple[float, float]:
    sign_ops = config.user_txs() + config.consensus_messages()
    verify_ops = config.user_txs() + config.consensus_messages() * (config.validators - 1)
    sign_ms = (sign_ops * sign_us) / 1000.0
    verify_ms = (verify_ops * verify_us) / 1000.0
    return sign_ms, verify_ms


def evaluate_two_party(
    config: LedgerConfig,
    sig_bytes: int = SIG_ALG_BYTES,
    timing: SchemeTiming | None = None,
) -> WorkloadResult:
    if timing is None and sig_bytes == SIG_ALG_BYTES:
        timing = measure_silmarils_us()

    user = config.user_txs()
    cons = config.consensus_messages()
    tx_auth = user * sig_bytes
    cons_auth = cons * sig_bytes
    total = tx_auth + cons_auth

    sign_ms = verify_ms = 0.0
    if timing is not None:
        sign_ms, verify_ms = _cpu_ms(config, timing.sign_us, timing.verify_us)

    return WorkloadResult(
        mode="two-party",
        sig_bytes_per_auth=sig_bytes,
        tx_auth_bytes=tx_auth,
        consensus_auth_bytes=cons_auth,
        total_auth_bytes_per_block=total,
        auth_kib_per_block=total / 1024.0,
        auth_mib_per_minute=(total * config.blocks_per_minute) / (1024 * 1024),
        est_sign_cpu_ms_per_block=sign_ms,
        est_verify_cpu_ms_per_block=verify_ms,
    )


@dataclass
class TpsResult:
    scheme: str
    cpu_tps: int
    bandwidth_tps: int
    combined_tps: int
    cpu_loss_pct: float
    bandwidth_loss_pct: float
    bottleneck: str


def _effective_tps(base: int, loss_pct: float) -> int:
    return max(1, round(base * (1.0 - loss_pct / 100.0)))


def _block_cap_loss(total_auth: int, cap: int) -> float:
    if total_auth <= cap:
        return 0.0
    return min(95.0, round(100.0 * (1.0 - cap / total_auth), 1))


def _network_loss(total_auth: int, blocks_per_min: float, mbps: float) -> float:
    if mbps <= 0:
        return 0.0
    auth_bps = (total_auth * blocks_per_min) / 60.0
    cap_bps = (mbps * 1_000_000) / 8.0
    if auth_bps <= cap_bps:
        return 0.0
    return min(95.0, round(100.0 * (1.0 - cap_bps / auth_bps), 1))


def evaluate_tps(
    config: LedgerConfig,
    workload: WorkloadResult,
    timing: SchemeTiming,
    base_tps: int,
    block_auth_cap: int,
    network_mbps: float,
    scheme_name: str,
    hybrid_cpu_loss: float | None = None,
) -> TpsResult:
    block_ms = config.block_time_ms()
    auth_cpu = workload.est_sign_cpu_ms_per_block + workload.est_verify_cpu_ms_per_block
    cpu_loss = (
        hybrid_cpu_loss
        if hybrid_cpu_loss is not None
        else min(95.0, round(100.0 * auth_cpu / block_ms, 1))
    )
    cap_loss = _block_cap_loss(workload.total_auth_bytes_per_block, block_auth_cap)
    net_loss = _network_loss(
        workload.total_auth_bytes_per_block, config.blocks_per_minute, network_mbps
    )
    bw_loss = max(cap_loss, net_loss)
    cpu_tps = _effective_tps(base_tps, cpu_loss)
    bw_tps = _effective_tps(base_tps, bw_loss)
    bottleneck = "cpu" if cpu_loss >= bw_loss else ("block cap" if cap_loss >= net_loss else "network")
    return TpsResult(
        scheme=scheme_name,
        cpu_tps=cpu_tps,
        bandwidth_tps=bw_tps,
        combined_tps=min(cpu_tps, bw_tps),
        cpu_loss_pct=cpu_loss,
        bandwidth_loss_pct=bw_loss,
        bottleneck=bottleneck,
    )
