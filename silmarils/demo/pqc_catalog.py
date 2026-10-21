"""Published PQC scheme metadata from the SILMARILS paper comparison table.

CPU latencies for measured PQ schemes come from ``simulation/output/pq_hardware_benchmark.json``
(same source as the paper TPS model). The web demo is separate from the paper simulator but
reuses that file when present. Schemes without a hardware row (e.g. Dilithium-3, SLH-DSA)
expose sizes only or illustrative placeholders.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

_SIM = Path(__file__).resolve().parent.parent / "simulation"
if str(_SIM) not in sys.path:
    sys.path.insert(0, str(_SIM))

from pq_benchmarks import HardwareBenchmarkError, resolve_pq_timing  # noqa: E402

_PQ_HW_KEYS = {
    "Dilithium-2 (ML-DSA-44)": "Dilithium-2",
    "Falcon-512": "Falcon-512",
    "SPHINCS+-128f": "SPHINCS+-128f",
    "SPHINCS+-128s": "SPHINCS+-128s",
}


class VerifierModel(str, Enum):
    TDV = "Designated verifier (TDV)"
    PUBLIC = "Public verifier"


@dataclass(frozen=True)
class SignatureScheme:
    name: str
    security_type: str
    pk_bytes: int
    sk_bytes: int
    sig_bytes: int
    verifier: VerifierModel
    assumptions: str
    sign_us: float | None = None
    verify_us: float | None = None

    @property
    def auth_bytes_per_tx(self) -> int:
        return self.sig_bytes

    @property
    def is_silmarils(self) -> bool:
        return self.name == "SILMARILS"


def _hardware_us(display_name: str) -> tuple[float | None, float | None]:
    key = _PQ_HW_KEYS.get(display_name)
    if key is None:
        return None, None
    try:
        t = resolve_pq_timing(key)
        return t.sign_us, t.verify_us
    except HardwareBenchmarkError:
        return None, None


# Sizes from Table 1 (IACR CIC). PQ CPU latencies from pq_hardware_benchmark.json when available.
SCHEMES: list[SignatureScheme] = [
    SignatureScheme(
        name="SILMARILS",
        security_type="Information-theoretic (TDV)",
        pk_bytes=96,
        sk_bytes=32,
        sig_bytes=128,
        verifier=VerifierModel.TDV,
        assumptions="TRNG + Shamir SSS",
        sign_us=18.0,
        verify_us=9.0,
    ),
    SignatureScheme(
        name="sr25519",
        security_type="Classical (ECDSA-like)",
        pk_bytes=32,
        sk_bytes=64,
        sig_bytes=64,
        verifier=VerifierModel.PUBLIC,
        assumptions="ECDLP / Curve25519",
        sign_us=45.0,
        verify_us=95.0,
    ),
    SignatureScheme(
        name="Dilithium-2 (ML-DSA-44)",
        security_type="Computational PQ",
        pk_bytes=1312,
        sk_bytes=2528,
        sig_bytes=2420,
        verifier=VerifierModel.PUBLIC,
        assumptions="Module-LWE",
        sign_us=_hardware_us("Dilithium-2 (ML-DSA-44)")[0],
        verify_us=_hardware_us("Dilithium-2 (ML-DSA-44)")[1],
    ),
    SignatureScheme(
        name="Dilithium-3 (ML-DSA-65)",
        security_type="Computational PQ",
        pk_bytes=1952,
        sk_bytes=4000,
        sig_bytes=3293,
        verifier=VerifierModel.PUBLIC,
        assumptions="Module-LWE",
    ),
    SignatureScheme(
        name="Falcon-512",
        security_type="Computational PQ",
        pk_bytes=897,
        sk_bytes=1281,
        sig_bytes=690,
        verifier=VerifierModel.PUBLIC,
        assumptions="SIS over NTRU lattices",
        sign_us=_hardware_us("Falcon-512")[0],
        verify_us=_hardware_us("Falcon-512")[1],
    ),
    SignatureScheme(
        name="SPHINCS+-128f",
        security_type="Computational PQ",
        pk_bytes=32,
        sk_bytes=64,
        sig_bytes=17088,
        verifier=VerifierModel.PUBLIC,
        assumptions="Hash-based (QROM)",
        sign_us=_hardware_us("SPHINCS+-128f")[0],
        verify_us=_hardware_us("SPHINCS+-128f")[1],
    ),
    SignatureScheme(
        name="SPHINCS+-128s",
        security_type="Computational PQ",
        pk_bytes=32,
        sk_bytes=64,
        sig_bytes=7856,
        verifier=VerifierModel.PUBLIC,
        assumptions="Hash-based (QROM)",
        sign_us=_hardware_us("SPHINCS+-128s")[0],
        verify_us=_hardware_us("SPHINCS+-128s")[1],
    ),
    SignatureScheme(
        name="SLH-DSA-128-24",
        security_type="Computational PQ",
        pk_bytes=32,
        sk_bytes=48,
        sig_bytes=3856,
        verifier=VerifierModel.PUBLIC,
        assumptions="Hash-based (limited sigs)",
        # Illustrative placeholder; not measured on author hardware (no pqcrypto SLH-DSA binding).
        sign_us=4100.0,
        verify_us=160.0,
    ),
]


def primary_comparison() -> list[SignatureScheme]:
    names = {
        "SILMARILS",
        "Dilithium-2 (ML-DSA-44)",
        "Falcon-512",
        "SPHINCS+-128f",
        "SPHINCS+-128s",
    }
    return [s for s in SCHEMES if s.name in names]
