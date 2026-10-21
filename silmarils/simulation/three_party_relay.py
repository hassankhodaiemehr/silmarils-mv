"""Three-party relay workload (Section 4.4, Algorithms alg:3p-sign .. alg:3p-transfer)."""

from __future__ import annotations

from dataclasses import dataclass

from constants import FIELD_BYTES, SIG_ALG_BYTES, LedgerConfig
from two_party_ledger import SchemeTiming, measure_silmarils_us, _cpu_ms, evaluate_two_party


@dataclass(frozen=True)
class IcMessageSizes:
    """Field-element counts from Protocol 18.7 composition (Table tab:3party-setup)."""

    p1_to_p2_fields: int = 4  # (x, x', sigma, sigma')
    p1_to_p3_fields: int = 3  # (k1, k2, k2')
    broadcast_fields: int = 3  # (e, x_e, sigma_e)
    transfer_fields: int = 7  # (sigma_alg x4, r, x, sigma)

    @property
    def wire_bytes_honest_path(self) -> int:
        """Authentication bytes on the wire per relayed user tx (M excluded)."""
        return (
            (self.p1_to_p2_fields + self.p1_to_p3_fields + self.broadcast_fields)
            * FIELD_BYTES
            + self.transfer_fields * FIELD_BYTES
        )

    @property
    def transfer_bytes(self) -> int:
        return self.transfer_fields * FIELD_BYTES


IC_SIZES = IcMessageSizes()


@dataclass
class ThreePartyRelayResult:
    ic_sizes: IcMessageSizes
    relay_auth_bytes_per_tx: int
    direct_auth_bytes_per_tx: int
    relay_ratio: float
    mixed_user_auth_bytes: int
    mixed_total_auth_bytes_per_block: int
    mixed_auth_kib_per_block: float
    overhead_vs_two_party_pct: float
    overhead_vs_two_party_bytes: int
    est_sign_cpu_ms_per_block: float
    est_verify_cpu_ms_per_block: float


# Analytic CPU: 2-party sign + IC (~8 field ops) + transfer verify (~6 ops + hash).
THREE_PARTY_SIGN_MULT = 1.35  # vs two-party sign
THREE_PARTY_VERIFY_MULT = 1.25  # vs two-party verify on transfer path


def evaluate_three_party_relay(
    config: LedgerConfig,
    relay_ratio: float = 1.0,
    timing: SchemeTiming | None = None,
) -> ThreePartyRelayResult:
    """Model user txs through P2 (mempool relay); consensus stays two-party direct."""
    if timing is None:
        timing = measure_silmarils_us()

    relay_bytes = IC_SIZES.wire_bytes_honest_path
    direct_bytes = SIG_ALG_BYTES
    user = config.user_txs()
    relayed = int(round(user * relay_ratio))
    direct = user - relayed

    mixed_user_auth = relayed * relay_bytes + direct * direct_bytes
    cons_auth = config.consensus_messages() * direct_bytes
    mixed_total = mixed_user_auth + cons_auth

    sign_ms, verify_ms = _cpu_ms(config, timing.sign_us, timing.verify_us)
    # Scale CPU for relayed fraction only.
    relay_frac = relayed / max(user, 1)
    sign_ms *= 1.0 + relay_frac * (THREE_PARTY_SIGN_MULT - 1.0)
    verify_ms *= 1.0 + relay_frac * (THREE_PARTY_VERIFY_MULT - 1.0)

    baseline_user = user * direct_bytes
    overhead_bytes = mixed_user_auth - baseline_user
    overhead_pct = 100.0 * overhead_bytes / max(baseline_user, 1)

    return ThreePartyRelayResult(
        ic_sizes=IC_SIZES,
        relay_auth_bytes_per_tx=relay_bytes,
        direct_auth_bytes_per_tx=direct_bytes,
        relay_ratio=relay_ratio,
        mixed_user_auth_bytes=mixed_user_auth,
        mixed_total_auth_bytes_per_block=mixed_total,
        mixed_auth_kib_per_block=mixed_total / 1024.0,
        overhead_vs_two_party_pct=overhead_pct,
        overhead_vs_two_party_bytes=overhead_bytes,
        est_sign_cpu_ms_per_block=sign_ms,
        est_verify_cpu_ms_per_block=verify_ms,
    )


def relay_bandwidth_curve(
    config: LedgerConfig,
    validator_counts: list[int],
    relay_ratio: float = 1.0,
) -> list[tuple[int, float, float]]:
    """Return (v, sil_two_party_kib, sil_three_party_kib) per validator count."""
    points = []
    for v in validator_counts:
        cfg = LedgerConfig(
            validators=v,
            tx_per_block=config.tx_per_block,
            blocks_per_minute=config.blocks_per_minute,
            consensus_rounds_per_block=config.consensus_rounds_per_block,
            user_tx_ratio=config.user_tx_ratio,
        )
        two = evaluate_two_party(cfg)
        three = evaluate_three_party_relay(cfg, relay_ratio=relay_ratio)
        points.append((v, two.auth_kib_per_block, three.mixed_auth_kib_per_block))
    return points
