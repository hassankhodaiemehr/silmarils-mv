"""Minimal two-party SILMARILS reference aligned with IACR CIC.tex (4-field core, pk=I)."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Tuple

P = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
    16,
)


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


def field_hash(*parts: bytes) -> int:
    digest = hashlib.sha256(b"".join(parts)).digest()
    return int.from_bytes(digest, "big") % P or 1


def derive_weights(identity: int) -> Tuple[int, int]:
    """H_w(I): two distinct nonzero field elements (Section 4.1)."""
    w0 = field_hash(identity.to_bytes(32, "big"), b"\x00")
    w1 = field_hash(identity.to_bytes(32, "big"), b"\x01")
    if w0 == w1:
        w1 = field_hash(identity.to_bytes(32, "big"), b"\x02")
    return w0, w1


def sss_share(secret: int, w0: int, w1: int, slope: int | None = None) -> Tuple[int, int]:
    a = _rand_field() if slope is None else slope % P
    s = secret % P
    return _mod(s + a * w0), _mod(s + a * w1)


def sss_reconstruct(share0: int, share1: int, w0: int, w1: int) -> int:
    return _mod((w0 * share1 - w1 * share0) * _mod_inv(w0 - w1))


def hmac_field(key: int, message: bytes) -> int:
    key_bytes = key.to_bytes(32, "big")
    digest = hmac.new(key_bytes, message, hashlib.sha256).digest()
    return int.from_bytes(digest, "big") % P or 1


@dataclass(frozen=True)
class SilmarilsKeys:
    signing_key: int
    session_key: int
    identity: int

    @property
    def weights(self) -> Tuple[int, int]:
        return derive_weights(self.identity)


@dataclass(frozen=True)
class SilmarilsSignature:
    sigma: Tuple[int, int, int, int]
    receipt: int


class Silmarils:
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
        w0, w1 = keys.weights
        r = self._receipt(message, keys)
        d = _rand_field()
        epsilon = _rand_field()
        eps0, eps1 = sss_share(epsilon, w0, w1)

        k_prime = hmac_field(keys.signing_key, message)
        k0, k1 = sss_share(k_prime, w0, w1)

        inv_eps = _mod_inv(epsilon)
        sigma1 = _mod(d * _mod_sub(k_prime, r))
        sigma2 = _mod(k1 * d)
        sigma3 = _mod(d * inv_eps * eps1)
        sigma4 = _mod(d * _mod_sub(k0, _mod(r * inv_eps * eps0)))

        return SilmarilsSignature(sigma=(sigma1, sigma2, sigma3, sigma4), receipt=r)

    def _verify_core(self, signature: SilmarilsSignature, r: int, w0: int, w1: int) -> bool:
        sigma1, sigma2, sigma3, sigma4 = signature.sigma
        if sigma3 == 0:
            return False
        v0 = _mod_sub(sigma1, sigma4)
        v1 = _mod(sigma1 - sigma2 + _mod(r * sigma3))
        return sss_reconstruct(v0, v1, w0, w1) == 0

    def verify(self, message: bytes, signature: SilmarilsSignature, keys: SilmarilsKeys) -> bool:
        w0, w1 = keys.weights
        r = self._receipt(message, keys)
        return self._verify_core(signature, r, w0, w1)

    def audit_verify(self, message: bytes, signature: SilmarilsSignature, identity: int) -> bool:
        w0, w1 = derive_weights(identity)
        return self._verify_core(signature, signature.receipt, w0, w1)
