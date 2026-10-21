//! Same-host signature baselines with the fastest PQClean implementations (AVX2 on x86_64 Linux/WSL),
//! plus the SILMARILS-MV core (Rust port of fe25519.h) at the parameters of the paper's Table VII.
//! Output: one JSON line per scheme.
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use rand::RngCore;
use std::time::Instant;

fn time_it<F: FnMut()>(min_iters: usize, min_secs: f64, mut f: F) -> (f64, usize) {
    for _ in 0..3 { f(); } // warm-up
    let t0 = Instant::now();
    let mut n = 0;
    while n < min_iters || t0.elapsed().as_secs_f64() < min_secs { f(); n += 1; }
    (t0.elapsed().as_secs_f64() * 1e6 / n as f64, n)
}

macro_rules! pq {
    ($name:expr, $m:path, $mi:expr) => {{
        use $m as s;
        let (pk, sk) = s::keypair();
        let mut msg = [0u8; 128];
        rand::thread_rng().fill_bytes(&mut msg);
        let mut sig = s::detached_sign(&msg, &sk);
        let (sign_us, ns) = time_it($mi, 2.0, || { msg[0] = msg[0].wrapping_add(1); sig = s::detached_sign(&msg, &sk); });
        let (verify_us, nv) = time_it($mi, 2.0, || { assert!(s::verify_detached_signature(&sig, &msg, &pk).is_ok()); });
        println!("{}", serde_json::json!({"scheme": $name, "impl": impl_name(), "pk": pk.as_bytes().len(),
            "sig": sig.as_bytes().len(), "sign_us": sign_us, "verify_us": verify_us, "n_sign": ns, "n_verify": nv}));
    }};
}

fn impl_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    { if std::is_x86_feature_detected!("avx2") && !cfg!(windows) { return "avx2"; } }
    "clean"
}

#[path = "../field.rs"]
mod field;
use field::{dot, powers, Fe};

fn main() {
    // Ed25519 (ed25519-dalek, verify_strict)
    {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = sk.verifying_key();
        let mut msg = [0u8; 128];
        rand::thread_rng().fill_bytes(&mut msg);
        let mut sig = sk.sign(&msg);
        let (sign_us, ns) = time_it(1000, 2.0, || { msg[0] = msg[0].wrapping_add(1); sig = sk.sign(&msg); });
        let (verify_us, nv) = time_it(1000, 2.0, || { assert!(vk.verify_strict(&msg, &sig).is_ok()); });
        println!("{}", serde_json::json!({"scheme": "Ed25519 (dalek)", "impl": "native", "pk": 32, "sig": 64,
            "sign_us": sign_us, "verify_us": verify_us, "n_sign": ns, "n_verify": nv}));
    }
    pq!("ML-DSA-44", pqcrypto_mldsa::mldsa44, 500);
    pq!("ML-DSA-65", pqcrypto_mldsa::mldsa65, 500);
    pq!("Falcon-512", pqcrypto_falcon::falcon512, 200);
    pq!("SPHINCS+-SHA2-128f-simple (SLH-DSA-SHA2-128f parameters)", pqcrypto_sphincsplus::sphincssha2128fsimple, 20);
    pq!("SPHINCS+-SHA2-128s-simple (SLH-DSA-SHA2-128s parameters)", pqcrypto_sphincsplus::sphincssha2128ssimple, 5);
    // SILMARILS-MV core, including SHA3-256 hashing of the 128-byte message
    use sha3::{Digest, Sha3_256};
    let mut rng = rand::thread_rng();
    for &(w, psi) in &[(1usize, 1usize), (1, 16), (3, 16), (10, 16), (20, 16), (33, 16), (66, 16), (10, 1), (10, 64)] {
        let a: Vec<Fe> = (0..(w + 1) * (psi + 1)).map(|_| Fe::random(&mut rng)).collect();
        let c: Vec<Fe> = (0..=w).map(|_| Fe::random(&mut rng)).collect();
        let b: Vec<Fe> = (0..=psi).map(|j| { let col: Vec<Fe> = (0..=w).map(|i| a[i * (psi + 1) + j]).collect(); dot(&c, &col) }).collect();
        let mut msg = [0u8; 128];
        rng.fill_bytes(&mut msg);
        let h2f = |m: &[u8]| { let d: [u8; 32] = Sha3_256::digest(m).into(); field::from_hash(&d) };
        let sign = |m: &[u8]| { let e = powers(&h2f(m), psi); (0..=w).map(|i| dot(&a[i * (psi + 1)..(i + 1) * (psi + 1)], &e)).collect::<Vec<Fe>>() };
        let mut alpha = sign(&msg);
        let (sign_us, ns) = time_it(2000, 1.0, || { msg[0] = msg[0].wrapping_add(1); alpha = sign(&msg); });
        let (verify_us, nv) = time_it(2000, 1.0, || {
            let e = powers(&h2f(&msg), psi);
            assert!(dot(&c, &alpha).eq(&dot(&b, &e)));
        });
        println!("{}", serde_json::json!({"scheme": "SILMARILS-MV (Rust)", "impl": "portable", "omega": w, "psi": psi,
            "sig": 32 * (w + 1), "sign_us": sign_us, "verify_us": verify_us, "n_sign": ns, "n_verify": nv, "incl_sha3": true}));
    }
}
