"""Minimal two-party SILMARILS reference for demo purposes (4-component core)."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Tuple

# 256-bit prime (same field size as the paper's k=256 instantiation).
P = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
    16,
)
W0 = 1
W1 = 2


def _mod(x: int) -> int:
    return x % P


def _mod_sub(a: int, b: int) -> int:
    return (a - b) % P


def _mod_inv(x: int) -> int:
    return pow(x % P, P - 2, P)


def _rand_field() -> int:
    while True:
        x = int.from_bytes(os.urandom(32), "big") % P
        if x != 0:
            return x


def sss_share(secret: int, slope: int | None = None) -> Tuple[int, int]:
    a = _rand_field() if slope is None else slope % P
    s = secret % P
    return _mod(s + a * W0), _mod(s + a * W1)


def sss_reconstruct(share0: int, share1: int) -> int:
    return _mod((W0 * share1 - W1 * share0) * _mod_inv(W0 - W1))


def field_hash(*parts: bytes) -> int:
    digest = hashlib.sha256(b"".join(parts)).digest()
    value = int.from_bytes(digest, "big") % P
    return value or 1


def hmac_field(key: int, message: bytes) -> int:
    key_bytes = key.to_bytes(32, "big")
    digest = hmac.new(key_bytes, message, hashlib.sha256).digest()
    value = int.from_bytes(digest, "big") % P
    return value or 1


@dataclass(frozen=True)
class SilmarilsKeys:
    signing_key: int
    session_key: int
    identity: int
    public_weights: Tuple[int, int] = (W0, W1)

    @property
    def public_key_bytes(self) -> int:
        """w0, w1, I = H(K) — three field elements."""
        return 3 * 32


@dataclass(frozen=True)
class SilmarilsSignature:
    sigma: Tuple[int, int, int, int]
    receipt: int

    @property
    def byte_size(self) -> int:
        return 4 * 32

    @property
    def ledger_transcript_bytes(self) -> int:
        """Published (sigma, r) on-chain."""
        return 5 * 32


class Silmarils:
    """Two-party TDV scheme between signer P1 and designated verifier P3."""

    def keygen(self) -> SilmarilsKeys:
        signing_key = _rand_field()
        return SilmarilsKeys(
            signing_key=signing_key,
            session_key=_rand_field(),
            identity=field_hash(signing_key.to_bytes(32, "big")),
        )

    def _receipt(self, message: bytes, keys: SilmarilsKeys) -> int:
        n = hmac_field(keys.session_key, message)
        return field_hash(message, n.to_bytes(32, "big"))

    def sign(self, message: bytes, keys: SilmarilsKeys) -> SilmarilsSignature:
        r = self._receipt(message, keys)
        d = _rand_field()
        epsilon = _rand_field()
        eps0, eps1 = sss_share(epsilon)

        k_prime = hmac_field(keys.signing_key, message)
        k0, k1 = sss_share(k_prime)

        inv_eps = _mod_inv(epsilon)

        sigma1 = _mod(d * _mod_sub(k_prime, r))
        sigma2 = _mod(k1 * d)
        sigma3 = _mod(d * inv_eps * eps1)
        sigma4 = _mod(d * _mod_sub(k0, _mod(r * inv_eps * eps0)))

        return SilmarilsSignature(
            sigma=(sigma1, sigma2, sigma3, sigma4),
            receipt=r,
        )

    def _verify_core(
        self, message: bytes, signature: SilmarilsSignature, r: int
    ) -> bool:
        sigma1, sigma2, sigma3, sigma4 = signature.sigma
        if sigma3 == 0:
            return False
        v0 = _mod_sub(sigma1, sigma4)
        v1 = _mod(sigma1 - sigma2 + _mod(r * sigma3))
        return sss_reconstruct(v0, v1) == 0

    def verify(self, message: bytes, signature: SilmarilsSignature, keys: SilmarilsKeys) -> bool:
        """Designated-verifier check (requires k_sig)."""
        r = self._receipt(message, keys)
        return self._verify_core(message, signature, r)

    def audit_verify(
        self,
        message: bytes,
        signature: SilmarilsSignature,
        keys: SilmarilsKeys | None = None,
    ) -> bool:
        """Public ledger audit on published (M, sigma, r) — no shared secrets."""
        return self._verify_core(message, signature, signature.receipt)

    def simulate(self, message: bytes, keys: SilmarilsKeys) -> SilmarilsSignature:
        """Designated verifier simulation (JSI property)."""
        r = self._receipt(message, keys)

        k_star = _rand_field()
        a_k = _rand_field()
        a_eps = _rand_field()
        d = _rand_field()
        epsilon = _rand_field()

        k0 = _mod(k_star + a_k * W0)
        k1 = _mod(k_star + a_k * W1)
        eps0 = _mod(epsilon + a_eps * W0)
        eps1 = _mod(epsilon + a_eps * W1)

        inv_eps = _mod_inv(epsilon)

        sigma1 = _mod(d * _mod_sub(k_star, r))
        sigma2 = _mod(k1 * d)
        sigma3 = _mod(d * inv_eps * eps1)
        sigma4 = _mod(d * _mod_sub(k0, _mod(r * inv_eps * eps0)))

        return SilmarilsSignature(
            sigma=(sigma1, sigma2, sigma3, sigma4),
            receipt=r,
        )


def smoke_test() -> None:
    scheme = Silmarils()
    keys = scheme.keygen()
    message = b"transfer 100 tokens to validator-3"

    real = scheme.sign(message, keys)
    simulated = scheme.simulate(message, keys)

    assert scheme.verify(message, real, keys)
    assert scheme.verify(message, simulated, keys)
    assert scheme.audit_verify(message, real)
    assert scheme.audit_verify(message, simulated)
    assert real.byte_size == 128
    assert real.ledger_transcript_bytes == 160


if __name__ == "__main__":
    smoke_test()
    print("SILMARILS core smoke test passed.")
