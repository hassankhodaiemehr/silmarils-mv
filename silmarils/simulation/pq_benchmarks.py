"""PQ signature CPU benchmarks from author hardware measurements only.

Requires ``output/pq_hardware_benchmark.json`` from ``benchmark_pq_hardware.py``.
Run that script before ``generate_paper_results.py`` or any TPS evaluation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

HARDWARE_JSON = Path(__file__).resolve().parent / "output" / "pq_hardware_benchmark.json"

REQUIRED_SCHEMES = frozenset(
    {"Dilithium-2", "Falcon-512", "SPHINCS+-128f", "SPHINCS+-128s"}
)


class HardwareBenchmarkError(RuntimeError):
    """Raised when the hardware benchmark file is missing or incomplete."""


@dataclass(frozen=True)
class ResolvedTiming:
    """Sign/verify latency for the TPS model with provenance."""

    sign_us: float
    verify_us: float
    source: str  # always "hardware"
    platform: str
    detail: str


def load_hardware_benchmark() -> dict:
    if not HARDWARE_JSON.is_file():
        raise HardwareBenchmarkError(
            f"Missing {HARDWARE_JSON.name} under output/. "
            "Run: python benchmark_pq_hardware.py"
        )
    return json.loads(HARDWARE_JSON.read_text(encoding="utf-8"))


def resolve_pq_timing(name: str) -> ResolvedTiming:
    """Return co-located sign/verify timing for *name* from the hardware JSON."""
    hw = load_hardware_benchmark()
    schemes = hw.get("schemes", {})
    if name not in schemes:
        raise HardwareBenchmarkError(
            f"Scheme {name!r} not found in {HARDWARE_JSON.name}. "
            "Re-run: python benchmark_pq_hardware.py"
        )
    row = schemes[name]
    plat = hw.get("platform", {})
    cpu = plat.get("cpu", "author hardware")
    when = hw.get("generated_at", "")[:10]
    return ResolvedTiming(
        sign_us=float(row["sign_us"]),
        verify_us=float(row["verify_us"]),
        source="hardware",
        platform=f"{cpu} ({when})" if when else cpu,
        detail=f"pqcrypto {hw.get('backend_version', '')} / {row.get('pqcrypto_module', '')}",
    )


def resolve_pq_timings(names: set[str] | None = None) -> dict[str, ResolvedTiming]:
    keys = names if names is not None else REQUIRED_SCHEMES
    missing = keys - REQUIRED_SCHEMES
    if missing:
        raise HardwareBenchmarkError(f"Unknown PQ scheme(s): {sorted(missing)}")
    load_hardware_benchmark()  # fail early before per-scheme lookups
    return {name: resolve_pq_timing(name) for name in sorted(keys)}


def timing_source_summary() -> str:
    hw = load_hardware_benchmark()
    plat = hw.get("platform", {})
    when = hw.get("generated_at", "")[:10]
    cpu = plat.get("cpu", "author hardware")
    return f"measured on {cpu} ({when}); pqcrypto {hw.get('backend_version', '')}"
