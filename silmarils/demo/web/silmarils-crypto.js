/* SILMARILS two-party TDV — browser port (4-component core, BigInt + Web Crypto) */
(function (global) {
  const P = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
  const W0 = 1n;
  const W1 = 2n;
  const P_MINUS_2 = P - 2n;

  function mod(x) {
    const v = typeof x === "bigint" ? x : BigInt(x);
    return ((v % P) + P) % P;
  }

  function modSub(a, b) {
    return mod(mod(a) - mod(b));
  }

  function modPow(base, exp) {
    let b = mod(base);
    let e = BigInt(exp);
    let r = 1n;
    while (e > 0n) {
      if (e & 1n) r = mod(r * b);
      b = mod(b * b);
      e >>= 1n;
    }
    return r;
  }

  function modInv(x) {
    return modPow(x, P_MINUS_2);
  }

  function bytesToBigInt(bytes) {
    let v = 0n;
    for (const b of bytes) v = (v << 8n) + BigInt(b);
    return v;
  }

  function bigIntTo32Bytes(n) {
    let hex = mod(n).toString(16).padStart(64, "0");
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
  }

  function randField() {
    const buf = new Uint8Array(32);
    let x = 0n;
    while (x === 0n) {
      crypto.getRandomValues(buf);
      x = mod(bytesToBigInt(buf));
    }
    return x;
  }

  function sssShare(secret, slope) {
    const a = slope == null ? randField() : mod(slope);
    const s = mod(secret);
    return [mod(s + a * W0), mod(s + a * W1)];
  }

  function sssReconstruct(share0, share1) {
    return mod((W0 * mod(share1) - W1 * mod(share0)) * modInv(W0 - W1));
  }

  async function sha256Field(parts) {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const buf = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
      buf.set(p, off);
      off += p.length;
    }
    const digest = await crypto.subtle.digest("SHA-256", buf);
    let v = mod(bytesToBigInt(new Uint8Array(digest)));
    return v === 0n ? 1n : v;
  }

  async function hmacField(key, messageBytes) {
    const keyBytes = bigIntTo32Bytes(key);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", cryptoKey, messageBytes);
    let v = mod(bytesToBigInt(new Uint8Array(sig)));
    return v === 0n ? 1n : v;
  }

  function encodeMessage(text) {
    return new TextEncoder().encode(text);
  }

  class Silmarils {
    async keygen() {
      const signingKey = randField();
      const identity = await sha256Field([bigIntTo32Bytes(signingKey)]);
      return { signingKey, sessionKey: randField(), identity };
    }

    async receipt(messageBytes, keys) {
      const n = await hmacField(keys.sessionKey, messageBytes);
      return sha256Field([messageBytes, bigIntTo32Bytes(n)]);
    }

    async sign(messageBytes, keys) {
      const r = await this.receipt(messageBytes, keys);
      const d = randField();
      const epsilon = randField();
      const [eps0, eps1] = sssShare(epsilon);
      const kPrime = await hmacField(keys.signingKey, messageBytes);
      const [k0, k1] = sssShare(kPrime);
      const invEps = modInv(epsilon);

      return {
        sigma: [
          mod(d * modSub(kPrime, r)),
          mod(k1 * d),
          mod(d * invEps * eps1),
          mod(d * modSub(k0, mod(r * invEps * eps0))),
        ],
        receipt: r,
        byteSize: 128,
        ledgerTranscriptBytes: 160,
      };
    }

    verifyCore(signature, r) {
      const [s1, s2, s3, s4] = signature.sigma;
      if (s3 === 0n) return false;
      const v0 = modSub(s1, s4);
      const v1 = mod(s1 - s2 + mod(r * s3));
      return sssReconstruct(v0, v1) === 0n;
    }

    async verify(messageBytes, signature, keys) {
      const r = await this.receipt(messageBytes, keys);
      return this.verifyCore(signature, r);
    }

    auditVerify(signature) {
      return this.verifyCore(signature, signature.receipt);
    }

    async simulate(messageBytes, keys) {
      const r = await this.receipt(messageBytes, keys);
      const kStar = randField();
      const aK = randField();
      const aEps = randField();
      const d = randField();
      const epsilon = randField();
      const k0 = mod(kStar + aK * W0);
      const k1 = mod(kStar + aK * W1);
      const eps0 = mod(epsilon + aEps * W0);
      const eps1 = mod(epsilon + aEps * W1);
      const invEps = modInv(epsilon);

      return {
        sigma: [
          mod(d * modSub(kStar, r)),
          mod(k1 * d),
          mod(d * invEps * eps1),
          mod(d * modSub(k0, mod(r * invEps * eps0))),
        ],
        receipt: r,
        byteSize: 128,
        ledgerTranscriptBytes: 160,
      };
    }
  }

  global.SilmarilsCrypto = { Silmarils, encodeMessage };
})(window);
