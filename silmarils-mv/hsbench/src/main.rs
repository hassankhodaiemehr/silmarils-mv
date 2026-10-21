//! hsbench: chained-HotStuff prototype with pluggable vote authentication, for the SILMARILS-MV paper.
//!
//! Schemes (topology):
//!   ed25519, mldsa44, sil-iv            star  (votes -> next leader, leader broadcasts QC in its proposal)
//!   mac, mac-tn, ed25519-a2a, mldsa44-a2a  all-to-all votes (every replica forms the QC locally)
//! mac-tn adds SILMARILS-MV threshold notarization: on commit, each replica releases a certificate share to
//! a rotating combiner, which interpolates, checks, and sends the certificate to external auditors.
//!
//! Replicas run as tokio tasks; messages travel over an emulated network with per-link one-way delay and
//! per-node egress bandwidth, charged with exact wire sizes. All cryptography is real.
mod field;
mod silmv;

use clap::Parser;
use field::{from_hash, powers, Fe};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time::{sleep_until, Duration, Instant};

type Hash = [u8; 32];

#[derive(Parser, Debug, Clone)]
struct Args {
    #[arg(long, default_value_t = 4)] n: usize,
    #[arg(long, default_value = "sil-iv")] scheme: String,
    #[arg(long, default_value_t = 400)] batch: u32,
    #[arg(long, default_value_t = 128)] tx_size: u32,
    #[arg(long, default_value_t = 0.0)] delay_ms: f64,
    #[arg(long, default_value_t = 0.0)] bw_mbps: f64,
    #[arg(long, default_value_t = 10.0)] duration: f64,
    #[arg(long, default_value_t = 3.0)] warmup: f64,
    #[arg(long, default_value_t = 0)] crash: usize,
    #[arg(long, default_value_t = 1000.0)] timeout_ms: f64,
    #[arg(long, default_value_t = 16)] psi: usize,
    #[arg(long, default_value_t = 16)] pool: usize,
    #[arg(long, default_value_t = 16)] tn_omega: usize,
    #[arg(long, default_value_t = 64)] tn_psi: usize,
    #[arg(long, default_value_t = 4)] auditors: usize,
    /// background key-issuance traffic per replica per committed block: none | auto | <bytes>
    #[arg(long, default_value = "none")] issuance: String,
    #[arg(long, default_value_t = 0)] threads: usize,
    #[arg(long, default_value = "")] tag: String,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Scheme { Ed, Mldsa, SilIv, Mac, MacTn, EdA2a, MldsaA2a }
impl Scheme {
    fn parse(s: &str) -> Scheme {
        match s {
            "ed25519" => Scheme::Ed, "mldsa44" => Scheme::Mldsa, "sil-iv" => Scheme::SilIv,
            "mac" => Scheme::Mac, "mac-tn" => Scheme::MacTn, "ed25519-a2a" => Scheme::EdA2a,
            "mldsa44-a2a" => Scheme::MldsaA2a, _ => panic!("unknown scheme {s}"),
        }
    }
    fn a2a(&self) -> bool { matches!(self, Scheme::Mac | Scheme::MacTn | Scheme::EdA2a | Scheme::MldsaA2a) }
}

// ---------------------------------------------------------------- messages
enum QcBody { Genesis, Sigs(Vec<(u16, Vec<u8>)>), SilAgg { signers: Vec<(u16, u32)>, alpha: Vec<Fe> }, Local }
#[derive(Clone)]
struct Qc { view: u64, hash: Hash, body: Arc<QcBody> }
impl Qc {
    fn wire(&self, n: usize) -> usize {
        8 + 32 + match &*self.body {
            QcBody::Genesis | QcBody::Local => 0,
            QcBody::Sigs(v) => v.iter().map(|(_, s)| 2 + s.len()).sum(),
            QcBody::SilAgg { signers, alpha } => (n + 7) / 8 + 4 * signers.len() + 32 * alpha.len(),
        }
    }
}
struct Block { view: u64, parent: Hash, justify: Qc, ntx: u32, payload: u32, hash: Hash, born: Instant }
enum VoteAuth { Sig(Arc<Vec<u8>>), Sil { k: u32, alpha: Vec<Fe> }, Mac(Fe) }
enum Msg {
    Proposal(Arc<Block>),
    Vote { view: u64, hash: Hash, voter: u16, auth: VoteAuth },
    NewView { view: u64, qc: Qc },
    Share { height: u64, hash: Hash, member: u16, share: Vec<Fe>, tag: Fe, committed: Instant },
    Cert { height: u64, hash: Hash, alpha: Vec<Fe>, committed: Instant },
    Filler,
}
struct Env { from: usize, msg: Msg }

// ---------------------------------------------------------------- network
struct Net {
    tx: Vec<UnboundedSender<Env>>,
    dq: Vec<UnboundedSender<(Instant, u64, Env)>>,
    seq: AtomicU64,
    delay: Duration,
    bw_bps: f64,
    nic: Vec<Mutex<Instant>>,
    bytes: Vec<AtomicU64>,
    crashed: Vec<bool>,
}
impl Net {
    fn send(&self, from: usize, to: usize, msg: Msg, size: usize) {
        if from == to { let _ = self.tx[to].send(Env { from, msg }); return; }
        self.bytes[from].fetch_add(size as u64, Ordering::Relaxed);
        if self.crashed[to] { return; }
        let now = Instant::now();
        let depart = if self.bw_bps > 0.0 {
            let mut g = self.nic[from].lock().unwrap();
            let start = if *g > now { *g } else { now };
            let d = start + Duration::from_secs_f64(size as f64 * 8.0 / self.bw_bps);
            *g = d;
            d
        } else { now };
        let arrive = depart + self.delay;
        if arrive <= now + Duration::from_micros(20) {
            let _ = self.tx[to].send(Env { from, msg });
        } else {
            let seq = self.seq.fetch_add(1, Ordering::Relaxed);
            let _ = self.dq[to].send((arrive, seq, Env { from, msg }));
        }
    }
}

/// Per-node delay queue: one task per receiver holds in-flight messages in a min-heap keyed by arrival time
/// (instead of one timer task per message), which keeps emulation overhead low for all-to-all traffic.
struct Pending(Instant, u64, Env);
impl PartialEq for Pending { fn eq(&self, o: &Self) -> bool { self.0 == o.0 && self.1 == o.1 } }
impl Eq for Pending {}
impl PartialOrd for Pending { fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(o)) } }
impl Ord for Pending { fn cmp(&self, o: &Self) -> std::cmp::Ordering { (o.0, o.1).cmp(&(self.0, self.1)) } }

async fn delayer(mut rx: UnboundedReceiver<(Instant, u64, Env)>, out: UnboundedSender<Env>) {
    let mut heap: std::collections::BinaryHeap<Pending> = std::collections::BinaryHeap::new();
    let far = Instant::now() + Duration::from_secs(86_400);
    let sleep = sleep_until(far);
    tokio::pin!(sleep);
    loop {
        let head = heap.peek().map(|p| p.0);
        if let Some(at) = head { if sleep.deadline() != at { sleep.as_mut().reset(at); } }
        tokio::select! {
            biased;
            m = rx.recv() => match m {
                Some((at, sq, e)) => {
                    heap.push(Pending(at, sq, e));
                    while let Ok((at, sq, e)) = rx.try_recv() { heap.push(Pending(at, sq, e)); }
                }
                None => break,
            },
            _ = &mut sleep, if head.is_some() => {
                let now = Instant::now();
                while heap.peek().map_or(false, |p| p.0 <= now) {
                    let p = heap.pop().unwrap();
                    let _ = out.send(p.2);
                }
                if heap.is_empty() { sleep.as_mut().reset(far); }
            }
        }
    }
}

// ---------------------------------------------------------------- shared context
struct Metrics {
    commits: Vec<(Instant, Instant, u32)>, // (commit time, born, ntx) at observer
    certs: Vec<(Instant, f64)>,            // (time, latency ms) at auditor 0
    cert_verify_ns: Vec<f64>,
    timeouts: u64,
    chains: HashMap<usize, Vec<Hash>>,
}
struct Ctx {
    a: Args, scheme: Scheme, n: usize, t: usize, q: usize,
    net: Net,
    ed_pk: Vec<ed25519_dalek::VerifyingKey>,
    ml_pk: Vec<pqcrypto_mldsa::mldsa44::PublicKey>,
    ivp: silmv::IvParams, tnp: silmv::TnParams,
    honest: Vec<usize>,
    metrics: Mutex<Metrics>,
    mac_key: Fe,
    issuance_bytes: usize,
    crypto_ns: AtomicU64,
}

fn vote_msg(view: u64, h: &Hash) -> [u8; 41] {
    let mut m = [0u8; 41];
    m[0] = b'V'; m[1..9].copy_from_slice(&view.to_le_bytes()); m[9..].copy_from_slice(h);
    m
}
fn sha(parts: &[&[u8]]) -> Hash { let mut h = Sha256::new(); for p in parts { h.update(p); } h.finalize().into() }
fn mac_tag(key: &Fe, from: usize, to: usize, mh: &Fe) -> Fe {
    // one-time polynomial MAC r*m + s with per-pair key (r,s); key material derivation is not timed
    let r = key.add(&Fe::from_u64((from * 65537 + to) as u64));
    r.mul(mh).add(key)
}

struct Keys {
    ed_sk: Option<ed25519_dalek::SigningKey>,
    ml_sk: Option<pqcrypto_mldsa::mldsa44::SecretKey>,
    iv_s: Option<silmv::IvSigner>, iv_v: Option<silmv::IvVerifier>,
    tn_m: Option<silmv::TnMember>, tn_v: Option<Arc<silmv::TnVerifier>>,
}

struct VoteSet { seen: HashSet<u16>, sigs: Vec<(u16, Arc<Vec<u8>>)>, sil: Vec<(u16, u32)>, alpha: Vec<Fe>, done: bool }

struct Replica {
    id: usize, ctx: Arc<Ctx>, keys: Keys,
    view: u64, voted_view: u64, proposed_view: u64,
    high_qc: Qc, locked_view: u64,
    blocks: HashMap<Hash, Arc<Block>>,
    last_committed: Hash, height: u64,
    votes: HashMap<(u64, Hash), VoteSet>,
    local_qcs: HashSet<(u64, Hash)>,
    pending: Vec<Arc<Block>>,
    newviews: HashMap<u64, HashSet<usize>>,
    vote_ctr: u64,
    shares: HashMap<u64, (Vec<(usize, Vec<Fe>)>, Instant, bool)>,
    deadline: Instant, timeout: Duration,
}

impl Replica {
    fn leader(&self, v: u64) -> usize { (v % self.ctx.n as u64) as usize }

    fn broadcast(&self, msg_fn: &dyn Fn() -> Msg, size: usize) {
        for to in 0..self.ctx.n { if to != self.id { self.ctx.net.send(self.id, to, msg_fn(), size); } }
    }

    fn propose(&mut self, v: u64) {
        if self.proposed_view >= v { return; }
        self.proposed_view = v;
        let a = &self.ctx.a;
        let qc = self.high_qc.clone();
        let payload = a.batch * a.tx_size;
        let hash = sha(&[&v.to_le_bytes(), &qc.hash, &qc.view.to_le_bytes(), &(self.id as u64).to_le_bytes(), &payload.to_le_bytes()]);
        let b = Arc::new(Block { view: v, parent: qc.hash, justify: qc, ntx: a.batch, payload, hash, born: Instant::now() });
        let size = 8 + 32 + 32 + 8 + b.justify.wire(self.ctx.n) + payload as usize;
        let bb = b.clone();
        self.broadcast(&|| Msg::Proposal(bb.clone()), size);
        self.on_proposal(self.id, b);
    }

    /// Ok(true) valid, Ok(false) invalid, Err(()) not yet verifiable (a2a: local QC missing)
    fn verify_qc(&self, qc: &Qc) -> Result<bool, ()> {
        let c = &self.ctx;
        match &*qc.body {
            QcBody::Genesis => Ok(true),
            QcBody::Local => if self.local_qcs.contains(&(qc.view, qc.hash)) { Ok(true) } else { Err(()) },
            QcBody::Sigs(sigs) => {
                if sigs.len() < c.q { return Ok(false); }
                let m = vote_msg(qc.view, &qc.hash);
                for (u, s) in sigs {
                    let ok = match c.scheme {
                        Scheme::Ed => {
                            let sig = ed25519_dalek::Signature::from_slice(s).unwrap();
                            c.ed_pk[*u as usize].verify_strict(&m, &sig).is_ok()
                        }
                        Scheme::Mldsa => {
                            use pqcrypto_traits::sign::DetachedSignature;
                            let sig = pqcrypto_mldsa::mldsa44::DetachedSignature::from_bytes(s).unwrap();
                            pqcrypto_mldsa::mldsa44::verify_detached_signature(&sig, &m, &c.ml_pk[*u as usize]).is_ok()
                        }
                        _ => false,
                    };
                    if !ok { return Ok(false); }
                }
                Ok(true)
            }
            QcBody::SilAgg { signers, alpha } => {
                if signers.len() < c.q { return Ok(false); }
                let e = powers(&from_hash(&sha(&[&vote_msg(qc.view, &qc.hash)])), c.ivp.psi);
                let sv: Vec<(usize, usize)> = signers.iter().map(|&(u, k)| (u as usize, k as usize)).collect();
                Ok(self.keys.iv_v.as_ref().unwrap().agg_verify(&c.ivp, &sv, &e, alpha))
            }
        }
    }

    fn on_proposal(&mut self, from: usize, b: Arc<Block>) {
        if from != self.leader(b.view) { return; }
        let t0 = std::time::Instant::now();
        let vr = self.verify_qc(&b.justify);
        self.ctx.crypto_ns.fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        match vr {
            Ok(true) => {}
            Ok(false) => return,
            Err(()) => { self.pending.push(b); return; }
        }
        self.blocks.insert(b.hash, b.clone());
        let qc = b.justify.clone();
        self.process_qc(&qc);
        if b.view > self.voted_view && b.justify.view >= self.locked_view {
            self.voted_view = b.view;
            self.vote(&b);
        }
        if b.view >= self.view { self.view = b.view + 1; self.deadline = Instant::now() + self.timeout; }
    }

    fn vote(&mut self, b: &Block) {
        let t0 = std::time::Instant::now();
        self.vote_inner(b);
        self.ctx.crypto_ns.fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }
    fn vote_inner(&mut self, b: &Block) {
        let c = self.ctx.clone();
        let m = vote_msg(b.view, &b.hash);
        let hdr = 8 + 32 + 2;
        if c.scheme.a2a() {
            match c.scheme {
                Scheme::Mac | Scheme::MacTn => {
                    let mh = from_hash(&sha(&[&m]));
                    for to in 0..c.n {
                        let tag = mac_tag(&c.mac_key, self.id, to, &mh);
                        c.net.send(self.id, to, Msg::Vote { view: b.view, hash: b.hash, voter: self.id as u16, auth: VoteAuth::Mac(tag) }, hdr + 32);
                    }
                }
                _ => {
                    let sig = Arc::new(self.sign_bytes(&m));
                    let sz = hdr + sig.len();
                    for to in 0..c.n {
                        c.net.send(self.id, to, Msg::Vote { view: b.view, hash: b.hash, voter: self.id as u16, auth: VoteAuth::Sig(sig.clone()) }, sz);
                    }
                }
            }
        } else {
            let to = self.leader(b.view + 1);
            let (auth, sz) = match c.scheme {
                Scheme::SilIv => {
                    let k = (self.vote_ctr / c.ivp.psi as u64) as u32;
                    self.vote_ctr += 1;
                    let e = powers(&from_hash(&sha(&[&m])), c.ivp.psi);
                    let a = &self.keys.iv_s.as_ref().unwrap().a[k as usize % c.ivp.k];
                    let alpha = silmv::sign_core(a, &e, c.ivp.w, c.ivp.psi);
                    let sz = hdr + 4 + 32 * alpha.len();
                    (VoteAuth::Sil { k, alpha }, sz)
                }
                _ => { let s = self.sign_bytes(&m); let sz = hdr + s.len(); (VoteAuth::Sig(Arc::new(s)), sz) }
            };
            c.net.send(self.id, to, Msg::Vote { view: b.view, hash: b.hash, voter: self.id as u16, auth }, sz);
        }
    }

    fn sign_bytes(&self, m: &[u8]) -> Vec<u8> {
        match self.ctx.scheme {
            Scheme::Ed | Scheme::EdA2a => {
                use ed25519_dalek::Signer;
                self.keys.ed_sk.as_ref().unwrap().sign(m).to_bytes().to_vec()
            }
            _ => {
                use pqcrypto_traits::sign::DetachedSignature;
                pqcrypto_mldsa::mldsa44::detached_sign(m, self.keys.ml_sk.as_ref().unwrap()).as_bytes().to_vec()
            }
        }
    }

    fn on_vote(&mut self, from: usize, view: u64, hash: Hash, voter: u16, auth: VoteAuth) {
        let c = self.ctx.clone();
        if voter as usize != from { return; }
        if !c.scheme.a2a() && self.leader(view + 1) != self.id { return; }
        if self.votes.get(&(view, hash)).map_or(false, |s| s.done || s.seen.contains(&voter)) { return; }
        let m = vote_msg(view, &hash);
        let t0 = std::time::Instant::now();
        let ok = match &auth {
            VoteAuth::Mac(tag) => {
                let mh = from_hash(&sha(&[&m]));
                mac_tag(&c.mac_key, from, self.id, &mh).eq(tag)
            }
            VoteAuth::Sig(s) => match c.scheme {
                Scheme::Ed | Scheme::EdA2a => {
                    let sig = ed25519_dalek::Signature::from_slice(s).unwrap();
                    c.ed_pk[voter as usize].verify_strict(&m, &sig).is_ok()
                }
                _ => {
                    use pqcrypto_traits::sign::DetachedSignature;
                    let sig = pqcrypto_mldsa::mldsa44::DetachedSignature::from_bytes(s).unwrap();
                    pqcrypto_mldsa::mldsa44::verify_detached_signature(&sig, &m, &c.ml_pk[voter as usize]).is_ok()
                }
            },
            VoteAuth::Sil { k, alpha } => {
                let e = powers(&from_hash(&sha(&[&m])), c.ivp.psi);
                self.keys.iv_v.as_ref().unwrap().verify(&c.ivp, voter as usize, *k as usize, &e, alpha)
            }
        };
        c.crypto_ns.fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        if !ok { return; }
        let w1 = c.ivp.w + 1;
        let set = self.votes.entry((view, hash)).or_insert_with(|| VoteSet {
            seen: HashSet::new(), sigs: vec![], sil: vec![], alpha: vec![Fe::ZERO; w1], done: false,
        });
        set.seen.insert(voter);
        match auth {
            VoteAuth::Sig(s) => set.sigs.push((voter, s)),
            VoteAuth::Sil { k, alpha } => {
                set.sil.push((voter, k));
                for (x, y) in set.alpha.iter_mut().zip(alpha.iter()) { *x = x.add(y); }
            }
            VoteAuth::Mac(_) => {}
        }
        if set.seen.len() >= c.q {
            set.done = true;
            let body = if c.scheme.a2a() {
                QcBody::Local
            } else if c.scheme == Scheme::SilIv {
                QcBody::SilAgg { signers: std::mem::take(&mut set.sil), alpha: std::mem::take(&mut set.alpha) }
            } else {
                QcBody::Sigs(set.sigs.drain(..).map(|(u, s)| (u, (*s).clone())).collect())
            };
            let qc = Qc { view, hash, body: Arc::new(body) };
            if c.scheme.a2a() { self.local_qcs.insert((view, hash)); }
            self.process_qc(&qc);
            if c.scheme.a2a() {
                let pend = std::mem::take(&mut self.pending);
                for b in pend { let f = self.leader(b.view); self.on_proposal(f, b); }
            }
            if self.leader(view + 1) == self.id { self.propose(view + 1); }
        }
    }

    fn process_qc(&mut self, qc: &Qc) {
        if qc.view > self.high_qc.view { self.high_qc = qc.clone(); }
        let b2 = match self.blocks.get(&qc.hash) { Some(b) => b.clone(), None => return };
        let b1 = match self.blocks.get(&b2.justify.hash) { Some(b) => b.clone(), None => return };
        if b1.view > self.locked_view { self.locked_view = b1.view; }
        let b0 = match self.blocks.get(&b1.justify.hash) { Some(b) => b.clone(), None => return };
        if b2.parent == b1.hash && b1.parent == b0.hash {
            // commit b0 and its uncommitted ancestors
            let mut chain = vec![];
            let mut cur = b0;
            loop {
                if cur.hash == self.last_committed || cur.view == 0 { break; }
                chain.push(cur.clone());
                match self.blocks.get(&cur.parent) { Some(p) => cur = p.clone(), None => break }
            }
            if chain.is_empty() { return; }
            for b in chain.into_iter().rev() { self.commit(&b); }
        }
    }

    fn commit(&mut self, b: &Arc<Block>) {
        self.last_committed = b.hash;
        self.height += 1;
        let now = Instant::now();
        let c = self.ctx.clone();
        {
            let mut mm = c.metrics.lock().unwrap();
            if self.id == 0 { mm.commits.push((now, b.born, b.ntx)); }
            let ch = mm.chains.entry(self.id).or_default();
            if ch.len() < 5000 { ch.push(b.hash); }
        }
        if c.issuance_bytes > 0 {
            let to = (self.id + 1) % c.n;
            c.net.send(self.id, to, Msg::Filler, c.issuance_bytes);
        }
        if c.scheme == Scheme::MacTn {
            let t0 = std::time::Instant::now();
            let h = self.height;
            let tp = &c.tnp;
            let k = (h / tp.psi as u64) as usize;
            let m = from_hash(&sha(&[b"C", &h.to_le_bytes(), &b.hash]));
            let e = powers(&m, tp.psi);
            let share = silmv::sign_core(&self.keys.tn_m.as_ref().unwrap().share[k % tp.k], &e, tp.w, tp.psi);
            let comb = c.honest[(h % c.honest.len() as u64) as usize];
            let tag = mac_tag(&c.mac_key, self.id, comb, &m);
            let sz = 8 + 32 + 2 + 32 * share.len() + 32;
            c.crypto_ns.fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
            c.net.send(self.id, comb, Msg::Share { height: h, hash: b.hash, member: self.id as u16, share, tag, committed: now }, sz);
        }
        // prune old blocks
        if self.height % 256 == 0 {
            let lim = b.view.saturating_sub(64);
            self.blocks.retain(|_, x| x.view >= lim || x.view == 0);
            self.votes.retain(|(v, _), _| *v >= lim);
            self.local_qcs.retain(|(v, _)| *v >= lim);
        }
    }

    fn on_share(&mut self, from: usize, height: u64, hash: Hash, member: u16, share: Vec<Fe>, tag: Fe, committed: Instant) {
        let c = self.ctx.clone();
        let t0 = std::time::Instant::now();
        let m = from_hash(&sha(&[b"C", &height.to_le_bytes(), &hash]));
        let okmac = mac_tag(&c.mac_key, from, self.id, &m).eq(&tag);
        c.crypto_ns.fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        if !okmac || member as usize != from { return; }
        let ent = self.shares.entry(height).or_insert_with(|| (vec![], committed, false));
        if ent.2 { return; }
        if committed < ent.1 { ent.1 = committed; }
        ent.0.push((member as usize, share));
        if ent.0.len() >= c.t + 1 {
            ent.2 = true;
            let t1 = std::time::Instant::now();
            let alpha = silmv::tn_combine(&ent.0, c.t);
            let e = powers(&m, c.tnp.psi);
            let k = (height / c.tnp.psi as u64) as usize;
            // optimistic check with an auditor key held by the combiner (fall back to decoding otherwise)
            let okc = self.keys.tn_v.as_ref().unwrap().verify(&c.tnp, k, &e, &alpha);
            c.crypto_ns.fetch_add(t1.elapsed().as_nanos() as u64, Ordering::Relaxed);
            if !okc { return; }
            let first = ent.1;
            let sz = 8 + 32 + 32 * alpha.len();
            for a in 0..c.a.auditors {
                c.net.send(self.id, c.n + a, Msg::Cert { height, hash, alpha: alpha.clone(), committed: first }, sz);
            }
            self.shares.remove(&height.saturating_sub(64));
        }
    }

    fn on_timeout(&mut self) {
        self.ctx.metrics.lock().unwrap().timeouts += 1;
        self.view += 1;
        self.timeout = self.timeout.mul_f64(1.5).min(Duration::from_secs(10));
        self.deadline = Instant::now() + self.timeout;
        let to = self.leader(self.view);
        let qc = self.high_qc.clone();
        let sz = 8 + qc.wire(self.ctx.n);
        let v = self.view;
        self.ctx.net.send(self.id, to, Msg::NewView { view: v, qc }, sz);
    }

    fn on_newview(&mut self, from: usize, view: u64, qc: Qc) {
        if self.leader(view) != self.id { return; }
        let t0 = std::time::Instant::now();
        let vr = self.verify_qc(&qc);
        self.ctx.crypto_ns.fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
        if let Ok(true) = vr { self.process_qc(&qc); }
        let set = self.newviews.entry(view).or_default();
        set.insert(from);
        if set.len() >= self.ctx.q {
            if self.view < view { self.view = view; }
            self.propose(view);
        }
    }

    async fn run(mut self, mut rx: UnboundedReceiver<Env>) {
        if self.leader(1) == self.id { self.propose(1); }
        loop {
            tokio::select! {
                env = rx.recv() => {
                    let Some(env) = env else { break };
                    let progressed_before = self.view;
                    match env.msg {
                        Msg::Proposal(b) => self.on_proposal(env.from, b),
                        Msg::Vote { view, hash, voter, auth } => self.on_vote(env.from, view, hash, voter, auth),
                        Msg::NewView { view, qc } => self.on_newview(env.from, view, qc),
                        Msg::Share { height, hash, member, share, tag, committed } => self.on_share(env.from, height, hash, member, share, tag, committed),
                        Msg::Cert { .. } | Msg::Filler => {}
                    }
                    if self.view > progressed_before { self.timeout = Duration::from_secs_f64(self.ctx.a.timeout_ms / 1000.0); }
                }
                _ = sleep_until(self.deadline) => self.on_timeout(),
            }
        }
    }
}

async fn auditor(idx: usize, ctx: Arc<Ctx>, key: Arc<silmv::TnVerifier>, mut rx: UnboundedReceiver<Env>) {
    while let Some(env) = rx.recv().await {
        if let Msg::Cert { height, hash, alpha, committed } = env.msg {
            let t0 = std::time::Instant::now();
            let m = from_hash(&sha(&[b"C", &height.to_le_bytes(), &hash]));
            let e = powers(&m, ctx.tnp.psi);
            let k = (height / ctx.tnp.psi as u64) as usize;
            let ok = key.verify(&ctx.tnp, k, &e, &alpha);
            let dt = t0.elapsed().as_nanos() as f64;
            if idx == 0 && ok {
                let now = Instant::now();
                let mut mm = ctx.metrics.lock().unwrap();
                mm.certs.push((now, (now - committed).as_secs_f64() * 1e3));
                mm.cert_verify_ns.push(dt);
            }
        }
    }
}

fn cpu_seconds() -> f64 {
    // utime + stime from /proc/self/stat (Linux/WSL); 0 elsewhere
    if let Ok(s) = std::fs::read_to_string("/proc/self/stat") {
        let rest = &s[s.rfind(')').unwrap() + 2..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        let tck = 100.0;
        return (f[11].parse::<f64>().unwrap_or(0.0) + f[12].parse::<f64>().unwrap_or(0.0)) / tck;
    }
    0.0
}

fn issuance_auto(s: Scheme, n: usize, t: usize, a: &Args) -> usize {
    // per-replica per-block issuance traffic from the paper's closed forms (malicious model d = n - 2t)
    let (nf, tf) = (n as f64, t as f64);
    let d = (nf - 2.0 * tf).max(1.0);
    let rc = nf * (nf - 1.0) / d;
    let mc = 2.0 * (nf - 1.0) + 2.0 * nf * (nf - 1.0) / d;
    match s {
        Scheme::SilIv => {
            let (w, psi) = (tf, a.psi as f64);
            let e = (w + 1.0) * (psi + 1.0);
            let idx = e * rc + e * mc + e * nf + nf * (psi + 1.0) * nf;
            ((nf + 1.0) / psi * idx * 32.0 / nf) as usize
        }
        Scheme::MacTn => {
            let (w, psi, nu) = (a.tn_omega as f64, a.tn_psi as f64, a.auditors as f64);
            let e = (w + 1.0) * (psi + 1.0);
            ((e * rc + e * mc + nu * (psi + 1.0) * nf) / psi * 32.0 / nf) as usize
        }
        _ => 0,
    }
}

fn main() {
    let a = Args::parse();
    let mut rt = tokio::runtime::Builder::new_multi_thread();
    if a.threads > 0 { rt.worker_threads(a.threads); }
    rt.enable_all().build().unwrap().block_on(run(a));
}

async fn run(a: Args) {
    let scheme = Scheme::parse(&a.scheme);
    let n = a.n;
    let t = (n - 1) / 3;
    let q = 2 * t + 1;
    assert!(a.crash <= t);
    let nodes = n + if scheme == Scheme::MacTn { a.auditors } else { 0 };
    let mut txs = vec![];
    let mut rxs = vec![];
    for _ in 0..nodes { let (s, r) = unbounded_channel(); txs.push(s); rxs.push(Some(r)); }
    let crashed: Vec<bool> = (0..nodes).map(|i| i < n && i >= n - a.crash).collect();
    let mut dqs = vec![];
    for i in 0..nodes {
        let (s, r) = unbounded_channel();
        dqs.push(s);
        tokio::spawn(delayer(r, txs[i].clone()));
    }
    let net = Net {
        dq: dqs, seq: AtomicU64::new(0),
        tx: txs, delay: Duration::from_secs_f64(a.delay_ms / 1000.0), bw_bps: a.bw_mbps * 1e6,
        nic: (0..nodes).map(|_| Mutex::new(Instant::now())).collect(),
        bytes: (0..nodes).map(|_| AtomicU64::new(0)).collect(), crashed: crashed.clone(),
    };
    // keys
    let t_setup = std::time::Instant::now();
    let mut rng = rand::rngs::OsRng;
    let (mut ed_sk, mut ed_pk, mut ml_sk, mut ml_pk) = (vec![], vec![], vec![], vec![]);
    if matches!(scheme, Scheme::Ed | Scheme::EdA2a) {
        for _ in 0..n { let k = ed25519_dalek::SigningKey::generate(&mut rng); ed_pk.push(k.verifying_key()); ed_sk.push(Some(k)); }
    }
    if matches!(scheme, Scheme::Mldsa | Scheme::MldsaA2a) {
        for _ in 0..n { let (p, s) = pqcrypto_mldsa::mldsa44::keypair(); ml_pk.push(p); ml_sk.push(Some(s)); }
    }
    let ivp = silmv::IvParams { n, w: t, psi: a.psi, k: a.pool };
    let tnp = silmv::TnParams { n, t, w: a.tn_omega, psi: a.tn_psi, k: a.pool };
    let (mut iv_s, mut iv_v): (Vec<Option<silmv::IvSigner>>, Vec<Option<silmv::IvVerifier>>) = (vec![], vec![]);
    if scheme == Scheme::SilIv {
        let (s, v) = silmv::iv_dealer(&ivp, 42);
        iv_s = s.into_iter().map(Some).collect(); iv_v = v.into_iter().map(Some).collect();
    }
    let (mut tn_m, mut tn_v): (Vec<Option<silmv::TnMember>>, Vec<Arc<silmv::TnVerifier>>) = (vec![], vec![]);
    if scheme == Scheme::MacTn {
        let (m, v) = silmv::tn_dealer(&tnp, a.auditors.max(1), 43);
        tn_m = m.into_iter().map(Some).collect(); tn_v = v.into_iter().map(Arc::new).collect();
    }
    let setup_s = t_setup.elapsed().as_secs_f64();
    let issuance_bytes = match a.issuance.as_str() {
        "none" => 0, "auto" => issuance_auto(scheme, n, t, &a), x => x.parse().unwrap(),
    };
    let honest: Vec<usize> = (0..n).filter(|&i| !crashed[i]).collect();
    let ctx = Arc::new(Ctx {
        a: a.clone(), scheme, n, t, q, net, ed_pk, ml_pk, ivp, tnp, honest,
        metrics: Mutex::new(Metrics { commits: vec![], certs: vec![], cert_verify_ns: vec![], timeouts: 0, chains: HashMap::new() }),
        mac_key: Fe::from_u64(0x5eed_1234_abcd), issuance_bytes, crypto_ns: AtomicU64::new(0),
    });
    let genesis = Qc { view: 0, hash: [0u8; 32], body: Arc::new(QcBody::Genesis) };
    let gblock = Arc::new(Block { view: 0, parent: [0u8; 32], justify: genesis.clone(), ntx: 0, payload: 0, hash: [0u8; 32], born: Instant::now() });
    let start = Instant::now();
    let mut handles = vec![];
    for i in 0..n {
        let rx = rxs[i].take().unwrap();
        if crashed[i] { continue; }
        let keys = Keys {
            ed_sk: ed_sk.get_mut(i).and_then(|x| x.take()),
            ml_sk: ml_sk.get_mut(i).and_then(|x| x.take()),
            iv_s: iv_s.get_mut(i).and_then(|x| x.take()),
            iv_v: iv_v.get_mut(i).and_then(|x| x.take()),
            tn_m: tn_m.get_mut(i).and_then(|x| x.take()),
            tn_v: tn_v.first().cloned(),
        };
        let mut blocks = HashMap::new();
        blocks.insert(gblock.hash, gblock.clone());
        let to = Duration::from_secs_f64(a.timeout_ms / 1000.0);
        let r = Replica {
            id: i, ctx: ctx.clone(), keys, view: 1, voted_view: 0, proposed_view: 0, high_qc: genesis.clone(), locked_view: 0,
            blocks, last_committed: [0u8; 32], height: 0, votes: HashMap::new(), local_qcs: HashSet::new(), pending: vec![],
            newviews: HashMap::new(), vote_ctr: 0, shares: HashMap::new(), deadline: start + to, timeout: to,
        };
        handles.push(tokio::spawn(r.run(rx)));
    }
    if scheme == Scheme::MacTn {
        for j in 0..a.auditors {
            let rx = rxs[n + j].take().unwrap();
            handles.push(tokio::spawn(auditor(j, ctx.clone(), tn_v[j].clone(), rx)));
        }
    }
    tokio::time::sleep(Duration::from_secs_f64(a.warmup)).await;
    let w0 = Instant::now();
    let b0: Vec<u64> = ctx.net.bytes.iter().map(|x| x.load(Ordering::Relaxed)).collect();
    let cpu0 = cpu_seconds();
    let cr0 = ctx.crypto_ns.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_secs_f64(a.duration)).await;
    let w1 = Instant::now();
    let b1: Vec<u64> = ctx.net.bytes.iter().map(|x| x.load(Ordering::Relaxed)).collect();
    let cpu1 = cpu_seconds();
    let cr1 = ctx.crypto_ns.load(Ordering::Relaxed);
    for h in &handles { h.abort(); }
    let m = ctx.metrics.lock().unwrap();
    let win: Vec<&(Instant, Instant, u32)> = m.commits.iter().filter(|(c, _, _)| *c >= w0 && *c < w1).collect();
    let nblocks = win.len();
    let ntx: u64 = win.iter().map(|x| x.2 as u64).sum();
    let mut lat: Vec<f64> = win.iter().map(|(c, b, _)| (*c - *b).as_secs_f64() * 1e3).collect();
    lat.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let pct = |v: &Vec<f64>, p: f64| if v.is_empty() { f64::NAN } else { v[((v.len() - 1) as f64 * p) as usize] };
    let mean = |v: &Vec<f64>| if v.is_empty() { f64::NAN } else { v.iter().sum::<f64>() / v.len() as f64 };
    let mut cl: Vec<f64> = m.certs.iter().filter(|(c, _)| *c >= w0 && *c < w1).map(|x| x.1).collect();
    cl.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let dur = (w1 - w0).as_secs_f64();
    let sent: Vec<f64> = (0..n).filter(|&i| !crashed[i]).map(|i| (b1[i] - b0[i]) as f64).collect();
    let per_blk = |x: f64| if nblocks > 0 { x / nblocks as f64 } else { f64::NAN };
    let avg_sent = sent.iter().sum::<f64>() / sent.len() as f64;
    let max_sent = sent.iter().cloned().fold(0.0, f64::max);
    // safety: all honest replicas committed identical prefixes
    let mut safety_ok = true;
    let mut min_len = usize::MAX;
    if let Some(r0) = m.chains.get(&0) {
        for ch in m.chains.values() {
            let l = ch.len().min(r0.len());
            min_len = min_len.min(ch.len());
            if ch[..l] != r0[..l] { safety_ok = false; }
        }
    }
    let out = serde_json::json!({
        "safety_ok": safety_ok, "min_committed": min_len, "replicas_committing": m.chains.len(),
        "tag": a.tag, "scheme": a.scheme, "n": n, "t": t, "crash": a.crash, "batch": a.batch, "tx_size": a.tx_size,
        "delay_ms": a.delay_ms, "bw_mbps": a.bw_mbps, "duration_s": dur, "issuance_bytes_per_block": issuance_bytes,
        "omega": if scheme == Scheme::SilIv { t } else if scheme == Scheme::MacTn { a.tn_omega } else { 0 },
        "psi": if scheme == Scheme::MacTn { a.tn_psi } else { a.psi },
        "blocks": nblocks, "tput_tx_s": ntx as f64 / dur, "blocks_s": nblocks as f64 / dur,
        "lat_mean_ms": mean(&lat), "lat_p50_ms": pct(&lat, 0.5), "lat_p99_ms": pct(&lat, 0.99),
        "cert_lat_mean_ms": mean(&cl), "cert_lat_p99_ms": pct(&cl, 0.99), "certs": cl.len(),
        "cert_verify_us": mean(&m.cert_verify_ns) / 1e3,
        "kib_per_replica_per_block_avg": per_blk(avg_sent) / 1024.0, "kib_per_replica_per_block_max": per_blk(max_sent) / 1024.0,
        "cpu_ms_per_block": per_blk((cpu1 - cpu0) * 1e3), "crypto_ms_per_block": per_blk((cr1 - cr0) as f64 / 1e6),
        "crypto_ms_per_replica_per_block": per_blk((cr1 - cr0) as f64 / 1e6) / (n - a.crash) as f64, "timeouts": m.timeouts, "setup_s": setup_s,
        "threads": a.threads,
    });
    println!("{}", out);
    std::process::exit(0);
}
