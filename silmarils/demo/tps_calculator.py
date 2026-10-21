"""TPS impact model for PQ signature schemes on blockchain hot paths."""

from __future__ import annotations

from dataclasses import dataclass

from blockchain_sim import LedgerConfig, evaluate_scheme
from pqc_catalog import SignatureScheme, primary_comparison


# Reference benchmarks from unbundled-signature / EternaX architecture narrative.
HYBRID_SILMARILS_TPS_LOSS_PCT = 2.0
FULL_PQ_RETROFIT_TPS_LOSS_PCT = 87.0  # mid-point of 84–90% industry range
DEFAULT_BLOCK_AUTH_CAP_BYTES = 256 * 1024
DEFAULT_NETWORK_MBPS = 100


@dataclass(frozen=True)
class TpsResult:
    scheme: str
    short_name: str
    is_silmarils: bool
    is_hybrid: bool
    base_tps: int
    effective_tps: int
    tps_loss_pct: float
    cpu_effective_tps: int
    bandwidth_effective_tps: int
    cpu_loss_pct: float
    bandwidth_loss_pct: float
    block_cap_loss_pct: float
    network_loss_pct: float
    bottleneck: str
    auth_bytes_per_block: int
    auth_cpu_ms_per_block: float
    block_time_ms: float
    bandwidth_mib_per_min: float
    model: str


def _block_time_ms(blocks_per_minute: float) -> float:
    return (60.0 / blocks_per_minute) * 1000.0


def _cpu_overhead_pct(auth_cpu_ms: float, block_time_ms: float) -> float:
    if block_time_ms <= 0:
        return 95.0
    return min(95.0, round(100.0 * auth_cpu_ms / block_time_ms, 1))


def _block_cap_loss_pct(total_auth_bytes: int, block_auth_cap_bytes: int) -> float:
    if total_auth_bytes <= block_auth_cap_bytes:
        return 0.0
    return min(95.0, round(100.0 * (1.0 - block_auth_cap_bytes / total_auth_bytes), 1))


def _network_loss_pct(
    total_auth_bytes: int,
    blocks_per_minute: float,
    network_mbps: float,
) -> float:
    if not network_mbps or network_mbps <= 0:
        return 0.0
    auth_bytes_per_sec = (total_auth_bytes * blocks_per_minute) / 60.0
    cap_bytes_per_sec = (network_mbps * 1_000_000) / 8.0
    if auth_bytes_per_sec <= cap_bytes_per_sec:
        return 0.0
    return min(95.0, round(100.0 * (1.0 - cap_bytes_per_sec / auth_bytes_per_sec), 1))


def _effective_tps(base_tps: int, loss_pct: float) -> int:
    return max(1, round(base_tps * (1.0 - loss_pct / 100.0)))


def _bottleneck_label(cpu_loss: float, block_cap_loss: float, network_loss: float) -> str:
    bw_loss = max(block_cap_loss, network_loss)
    if cpu_loss >= bw_loss:
        if bw_loss == 0 and cpu_loss == 0:
            return "none"
        return "cpu"
    if block_cap_loss >= network_loss:
        return "block cap"
    return "network"


def calculate_scheme_tps(
    scheme: SignatureScheme,
    config: LedgerConfig,
    base_tps: int,
    block_auth_cap_bytes: int = DEFAULT_BLOCK_AUTH_CAP_BYTES,
    network_mbps: float = DEFAULT_NETWORK_MBPS,
) -> TpsResult:
    metrics = evaluate_scheme(scheme, config)
    block_ms = _block_time_ms(config.blocks_per_minute)
    auth_cpu = metrics.est_sign_cpu_ms_per_block + metrics.est_verify_cpu_ms_per_block
    cpu_loss = _cpu_overhead_pct(auth_cpu, block_ms)
    block_cap_loss = _block_cap_loss_pct(
        metrics.total_auth_bytes_per_block, block_auth_cap_bytes
    )
    network_loss = _network_loss_pct(
        metrics.total_auth_bytes_per_block,
        config.blocks_per_minute,
        network_mbps,
    )
    bw_loss = max(block_cap_loss, network_loss)
    cpu_tps = _effective_tps(base_tps, cpu_loss)
    bw_tps = _effective_tps(base_tps, bw_loss)
    combined_loss = max(cpu_loss, bw_loss)

    return TpsResult(
        scheme=scheme.name,
        short_name=scheme.name.split(" (")[0],
        is_silmarils=scheme.is_silmarils,
        is_hybrid=False,
        base_tps=base_tps,
        effective_tps=min(cpu_tps, bw_tps),
        tps_loss_pct=combined_loss,
        cpu_effective_tps=cpu_tps,
        bandwidth_effective_tps=bw_tps,
        cpu_loss_pct=cpu_loss,
        bandwidth_loss_pct=bw_loss,
        block_cap_loss_pct=block_cap_loss,
        network_loss_pct=network_loss,
        bottleneck=_bottleneck_label(cpu_loss, block_cap_loss, network_loss),
        auth_bytes_per_block=metrics.total_auth_bytes_per_block,
        auth_cpu_ms_per_block=round(auth_cpu, 1),
        block_time_ms=round(block_ms, 1),
        bandwidth_mib_per_min=round(metrics.total_auth_mib_per_minute, 2),
        model="CPU + block auth cap + network link",
    )


def calculate_hybrid_stack_tps(
    config: LedgerConfig,
    base_tps: int,
    block_auth_cap_bytes: int = DEFAULT_BLOCK_AUTH_CAP_BYTES,
    network_mbps: float = DEFAULT_NETWORK_MBPS,
) -> TpsResult:
    """Unbundled architecture: SILMARILS hot path + SLH-DSA session anchors."""
    sil = next(s for s in primary_comparison() if s.is_silmarils)
    metrics = evaluate_scheme(sil, config)
    block_ms = _block_time_ms(config.blocks_per_minute)
    block_cap_loss = _block_cap_loss_pct(
        metrics.total_auth_bytes_per_block, block_auth_cap_bytes
    )
    network_loss = _network_loss_pct(
        metrics.total_auth_bytes_per_block,
        config.blocks_per_minute,
        network_mbps,
    )
    bw_loss = max(block_cap_loss, network_loss)
    cpu_tps = _effective_tps(base_tps, HYBRID_SILMARILS_TPS_LOSS_PCT)
    bw_tps = _effective_tps(base_tps, bw_loss)
    combined_loss = max(HYBRID_SILMARILS_TPS_LOSS_PCT, bw_loss)
    bottleneck = (
        "bandwidth"
        if bw_loss > HYBRID_SILMARILS_TPS_LOSS_PCT
        else "architecture (2%)"
    )

    return TpsResult(
        scheme="SILMARILS Hybrid (hot path + SLH-DSA anchors)",
        short_name="SILMARILS Hybrid",
        is_silmarils=True,
        is_hybrid=True,
        base_tps=base_tps,
        effective_tps=min(cpu_tps, bw_tps),
        tps_loss_pct=combined_loss,
        cpu_effective_tps=cpu_tps,
        bandwidth_effective_tps=bw_tps,
        cpu_loss_pct=HYBRID_SILMARILS_TPS_LOSS_PCT,
        bandwidth_loss_pct=bw_loss,
        block_cap_loss_pct=block_cap_loss,
        network_loss_pct=network_loss,
        bottleneck=bottleneck,
        auth_bytes_per_block=metrics.total_auth_bytes_per_block,
        auth_cpu_ms_per_block=round(
            metrics.est_sign_cpu_ms_per_block + metrics.est_verify_cpu_ms_per_block,
            1,
        ),
        block_time_ms=round(block_ms, 1),
        bandwidth_mib_per_min=round(metrics.total_auth_mib_per_minute, 2),
        model="Unbundled stack (~2% CPU + bandwidth caps)",
    )


def calculate_full_pq_retrofit_tps(base_tps: int) -> TpsResult:
    """Full public PQ on every hot-path transaction (industry retrofit scenario)."""
    effective = _effective_tps(base_tps, FULL_PQ_RETROFIT_TPS_LOSS_PCT)
    return TpsResult(
        scheme="Full PQ retrofit (ML-DSA on every tx)",
        short_name="Full PQ retrofit",
        is_silmarils=False,
        is_hybrid=False,
        base_tps=base_tps,
        effective_tps=effective,
        tps_loss_pct=FULL_PQ_RETROFIT_TPS_LOSS_PCT,
        cpu_effective_tps=effective,
        bandwidth_effective_tps=effective,
        cpu_loss_pct=FULL_PQ_RETROFIT_TPS_LOSS_PCT,
        bandwidth_loss_pct=FULL_PQ_RETROFIT_TPS_LOSS_PCT,
        block_cap_loss_pct=0.0,
        network_loss_pct=0.0,
        bottleneck="industry benchmark",
        auth_bytes_per_block=0,
        auth_cpu_ms_per_block=0.0,
        block_time_ms=0.0,
        bandwidth_mib_per_min=0.0,
        model="Industry benchmark (84–90% TPS loss under PQ migration)",
    )


def build_tps_comparison(
    base_tps: int = 10000,
    validators: int = 7,
    tx_per_block: int = 500,
    blocks_per_minute: float = 2.0,
    consensus_rounds_per_block: int = 3,
    block_auth_cap_bytes: int = DEFAULT_BLOCK_AUTH_CAP_BYTES,
    network_mbps: float = DEFAULT_NETWORK_MBPS,
) -> dict:
    config = LedgerConfig(
        validators=validators,
        tx_per_block=tx_per_block,
        blocks_per_minute=blocks_per_minute,
        consensus_rounds_per_block=consensus_rounds_per_block,
    )

    scheme_results = [
        calculate_scheme_tps(
            s, config, base_tps, block_auth_cap_bytes, network_mbps
        )
        for s in primary_comparison()
    ]
    hybrid = calculate_hybrid_stack_tps(
        config, base_tps, block_auth_cap_bytes, network_mbps
    )
    retrofit = calculate_full_pq_retrofit_tps(base_tps)

    dilithium = next(r for r in scheme_results if "Dilithium-2" in r.scheme)
    silmarils = next(r for r in scheme_results if r.is_silmarils)

    return {
        "base_tps": base_tps,
        "block_auth_cap_bytes": block_auth_cap_bytes,
        "network_mbps": network_mbps,
        "ledger_config": {
            "validators": validators,
            "tx_per_block": tx_per_block,
            "blocks_per_minute": blocks_per_minute,
            "block_time_ms": round(_block_time_ms(blocks_per_minute), 1),
        },
        "schemes": [r.__dict__ for r in scheme_results],
        "hybrid_stack": hybrid.__dict__,
        "full_pq_retrofit": retrofit.__dict__,
        "highlights": {
            "hybrid_effective_tps": hybrid.effective_tps,
            "retrofit_effective_tps": retrofit.effective_tps,
            "dilithium_effective_tps": dilithium.effective_tps,
            "silmarils_effective_tps": silmarils.effective_tps,
            "hybrid_vs_retrofit_tps_gain_pct": round(
                100
                * (hybrid.effective_tps - retrofit.effective_tps)
                / max(retrofit.effective_tps, 1),
                1,
            ),
        },
    }
