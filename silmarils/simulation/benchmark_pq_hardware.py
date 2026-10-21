#!/usr/bin/env python3
"""Measure post-quantum signature latencies on local hardware.

Uses the ``pqcrypto`` package (PQClean ``clean'' reference implementations).
Writes ``output/pq_hardware_benchmark.json`` for consumption by
``pq_benchmarks.py`` / ``two_party_ledger.py``.

Run from this directory::

    python benchmark_pq_hardware.py

Requires ``pqcrypto`` (see ``requirements.txt``).
"""

from __future__ import annotations

import json
import platform
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
OUTPUT_PATH = ROOT / "output" / "pq_hardware_benchmark.json"

DEFAULT_MESSAGE = b"permissioned-ledger transaction payload"


@dataclass(frozen=True)
class SchemeSpec:
    """One PQ scheme to benchmark."""

    display_name: str
    module_name: str
    pqcrypto_module: str
    samples_sign: int = 200
    samples_verify: int = 200
    samples_paired: int = 200


SCHEMES: tuple[SchemeSpec, ...] = (
    SchemeSpec("Dilithium-2", "ml_dsa_44", "pqcrypto.sign.ml_dsa_44"),
    SchemeSpec("Falcon-512", "falcon_512", "pqcrypto.sign.falcon_512"),
  # SPHINCS+ signing is orders of magnitude slower; fewer iterations.
    SchemeSpec(
        "SPHINCS+-128f",
        "sphincs_sha2_128f_simple",
        "pqcrypto.sign.sphincs_sha2_128f_simple",
        samples_sign=30,
        samples_verify=50,
        samples_paired=20,
    ),
    SchemeSpec(
        "SPHINCS+-128s",
        "sphincs_sha2_128s_simple",
        "pqcrypto.sign.sphincs_sha2_128s_simple",
        samples_sign=5,
        samples_verify=20,
        samples_paired=3,
    ),
)


@dataclass
class OpTimings:
    sign_us: float
    verify_us: float
    paired_op_us: float
    sign_median_us: float
    verify_median_us: float
    paired_median_us: float


def _cpu_name() -> str:
    if sys.platform == "win32":
        try:
            proc = subprocess.run(
                ["wmic", "cpu", "get", "Name", "/value"],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in proc.stdout.splitlines():
                if line.startswith("Name="):
                    return line.split("=", 1)[1].strip()
        except OSError:
            pass
    return platform.processor() or "unknown"


def _import_scheme(module_path: str) -> Any:
    parts = module_path.split(".")
    mod = __import__(module_path, fromlist=[parts[-1]])
    return mod


def _time_us(fn: Callable[[], None], iterations: int) -> tuple[float, float]:
    """Return (mean_us, median_us) over *iterations* calls."""
    samples: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1_000_000)
    return statistics.mean(samples), statistics.median(samples)


def benchmark_scheme(spec: SchemeSpec, message: bytes = DEFAULT_MESSAGE) -> dict[str, Any]:
    mod = _import_scheme(spec.pqcrypto_module)
    pk, sk = mod.generate_keypair()

    sig = mod.sign(sk, message)
    if not mod.verify(pk, message, sig):
        raise RuntimeError(f"{spec.display_name}: verify failed after sign")

    sign_mean, sign_median = _time_us(lambda: mod.sign(sk, message), spec.samples_sign)
    sig = mod.sign(sk, message)
    verify_mean, verify_median = _time_us(
        lambda: mod.verify(pk, message, sig), spec.samples_verify
    )

    def paired() -> None:
        s = mod.sign(sk, message)
        if not mod.verify(pk, message, s):
            raise RuntimeError(f"{spec.display_name}: paired verify failed")

    paired_mean, paired_median = _time_us(paired, spec.samples_paired)

    note = None
    if spec.samples_paired < 200:
        note = (
            f"Reduced iterations (sign={spec.samples_sign}, verify={spec.samples_verify}, "
            f"paired={spec.samples_paired}) due to slow PQClean reference implementation."
        )

    return {
        "display_name": spec.display_name,
        "pqcrypto_module": spec.pqcrypto_module,
        "sign_us": round(sign_mean, 2),
        "verify_us": round(verify_mean, 2),
        "paired_op_us": round(paired_mean, 2),
        "sign_median_us": round(sign_median, 2),
        "verify_median_us": round(verify_median, 2),
        "paired_median_us": round(paired_median, 2),
        "samples_sign": spec.samples_sign,
        "samples_verify": spec.samples_verify,
        "samples_paired": spec.samples_paired,
        "public_key_bytes": mod.PUBLIC_KEY_SIZE,
        "secret_key_bytes": mod.SECRET_KEY_SIZE,
        "signature_bytes": mod.SIGNATURE_SIZE,
        "note": note,
    }


def collect_platform_info() -> dict[str, str]:
    return {
        "cpu": _cpu_name(),
        "os": platform.platform(),
        "python": platform.python_version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    }


def main() -> int:
    try:
        import pqcrypto  # noqa: F401
    except ImportError:
        print(
            "ERROR: pqcrypto is not installed. Run: pip install pqcrypto",
            file=sys.stderr,
        )
        return 1

    import importlib.metadata

    backend_version = importlib.metadata.version("pqcrypto")

    platform_info = collect_platform_info()
    print(f"Platform: {platform_info['cpu']}")
    print(f"OS: {platform_info['os']}")
    print(f"Python: {platform_info['python']}")
    print(f"Backend: pqcrypto {backend_version}")
    print()

    scheme_results: dict[str, Any] = {}
    failures: list[str] = []

    for spec in SCHEMES:
        print(f"Benchmarking {spec.display_name} ...", flush=True)
        try:
            result = benchmark_scheme(spec)
            scheme_results[spec.display_name] = result
            print(
                f"  sign={result['sign_us']:.1f} us  "
                f"verify={result['verify_us']:.1f} us  "
                f"paired={result['paired_op_us']:.1f} us"
            )
            if result.get("note"):
                print(f"  note: {result['note']}")
        except Exception as exc:  # noqa: BLE001 — report and continue
            failures.append(f"{spec.display_name}: {exc}")
            print(f"  FAILED: {exc}", file=sys.stderr)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "methodology": (
            "PQClean reference implementations via pqcrypto; "
            "perf_counter mean over independent sign/verify/paired loops. "
            "Simulator uses sign_us and verify_us separately for TPS."
        ),
        "backend": "pqcrypto",
        "backend_version": backend_version,
        "platform": platform_info,
        "message_len_bytes": len(DEFAULT_MESSAGE),
        "schemes": scheme_results,
        "failures": failures,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print()
    print(f"Wrote {OUTPUT_PATH}")

    if failures and not scheme_results:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
