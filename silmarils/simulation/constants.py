"""Paper-aligned SILMARILS parameters (IACR CIC.tex, k=256)."""

from __future__ import annotations

from dataclasses import dataclass

# Security parameter and field encoding (Section 4.1, Section 9).
K_BITS = 256
FIELD_BYTES = K_BITS // 8  # 32

# Artifact sizes (Table tab:merged_comparison_enhanced).
SK_BYTES = FIELD_BYTES  # K
PK_BYTES = FIELD_BYTES  # I = H(K); weights H_w(I) recomputed, not stored
SIG_ALG_BYTES = 4 * FIELD_BYTES  # sigma_alg = (sigma_1..sigma_4)
RECEIPT_BYTES = FIELD_BYTES  # r
IDENTITY_BYTES = FIELD_BYTES  # I on-chain

# Ledger transcript (Section 4.4): (M, sigma_alg, r, I) — M excluded from auth-byte counts.
LEDGER_FIELD_BYTES = SIG_ALG_BYTES + RECEIPT_BYTES + IDENTITY_BYTES  # 192

# Default permissioned-ledger simulator (Section 9).
DEFAULT_VALIDATORS = 7
DEFAULT_TX_PER_BLOCK = 500
DEFAULT_BLOCKS_PER_MINUTE = 2.0
DEFAULT_CONSENSUS_ROUNDS = 3
DEFAULT_USER_TX_RATIO = 0.85
DEFAULT_BASE_TPS = 10_000
DEFAULT_BLOCK_AUTH_CAP_BYTES = 256 * 1024
DEFAULT_NETWORK_MBPS = 100

# Hybrid / industry benchmarks cited in Section 9.
HYBRID_TPS_LOSS_PCT = 2.0
FULL_PQ_RETROFIT_TPS_LOSS_PCT = 87.0

# Dilithium-2 reference (Table 1).
DILITHIUM2_SIG_BYTES = 2420

# PQ signature sizes (Table tab:merged_comparison_enhanced) for bandwidth curves.
PQ_SIG_BYTES: dict[str, int] = {
    "Falcon-512": 690,
    "Dilithium-2": DILITHIUM2_SIG_BYTES,
    "Dilithium-3": 3293,
    "SLH-DSA-128-24": 3856,
    "SPHINCS+-128s": 7856,
    "SLH-DSA-192-24": 7752,
    "SPHINCS+-128f": 17088,
    "SLH-DSA-256-24": 14944,
}

# LaTeX macro suffix for each PQ scheme workload curve.
PQ_WORKLOAD_MACROS: dict[str, str] = {
    "Falcon-512": "Fal",
    "Dilithium-2": "Dil",
    "Dilithium-3": "DilThree",
    "SLH-DSA-128-24": "SlhI",
    "SPHINCS+-128s": "SphSmall",
    "SLH-DSA-192-24": "SlhII",
    "SPHINCS+-128f": "SphFast",
    "SLH-DSA-256-24": "SlhIII",
}


@dataclass(frozen=True)
class LedgerConfig:
    validators: int = DEFAULT_VALIDATORS
    tx_per_block: int = DEFAULT_TX_PER_BLOCK
    blocks_per_minute: float = DEFAULT_BLOCKS_PER_MINUTE
    consensus_rounds_per_block: int = DEFAULT_CONSENSUS_ROUNDS
    user_tx_ratio: float = DEFAULT_USER_TX_RATIO

    def user_txs(self) -> int:
        return int(self.tx_per_block * self.user_tx_ratio)

    def consensus_messages(self) -> int:
        # BFT-style: each validator attests to each peer per round.
        v = self.validators
        return v * (v - 1) * self.consensus_rounds_per_block

    def block_time_ms(self) -> float:
        return (60.0 / self.blocks_per_minute) * 1000.0
