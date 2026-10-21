/* PQC catalog + ledger/TPS models (static, no backend) */
(function (global) {
  const PRIMARY = [
    {
      name: "SILMARILS",
      shortName: "SILMARILS",
      pkBytes: 96,
      sigBytes: 160,
      isSilmarils: true,
      isPublic: false,
      signUs: 18,
      verifyUs: 9,
    },
    {
      name: "Dilithium-2 (ML-DSA-44)",
      shortName: "Dilithium-2",
      pkBytes: 1312,
      sigBytes: 2420,
      isSilmarils: false,
      isPublic: true,
      signUs: 210,
      verifyUs: 145,
    },
    {
      name: "Falcon-512",
      shortName: "Falcon-512",
      pkBytes: 897,
      sigBytes: 690,
      isSilmarils: false,
      isPublic: true,
      signUs: 380,
      verifyUs: 55,
    },
    {
      name: "SPHINCS+-128f",
      shortName: "SPHINCS+-128f",
      pkBytes: 32,
      sigBytes: 17088,
      isSilmarils: false,
      isPublic: true,
      signUs: 5200,
      verifyUs: 180,
    },
    {
      name: "SPHINCS+-128s",
      shortName: "SPHINCS+-128s",
      pkBytes: 32,
      sigBytes: 7856,
      isSilmarils: false,
      isPublic: true,
      signUs: 180000,
      verifyUs: 420,
    },
  ];

  const HYBRID_CPU_LOSS = 2.0;
  const RETROFIT_LOSS = 87.0;

  function round1(x) {
    return Math.round(x * 10) / 10;
  }

  function consensusMessages(validators, rounds) {
    return validators * (validators - 1) * rounds;
  }

  function evaluateScheme(scheme, cfg) {
    const userTxs = Math.floor(cfg.txPerBlock * cfg.userTxRatio);
    const consensus = consensusMessages(cfg.validators, cfg.consensusRounds);
    const txAuth = userTxs * scheme.sigBytes;
    const consensusAuth = consensus * scheme.sigBytes;
    const totalAuth = txAuth + consensusAuth;
    const signOps = userTxs + consensus;
    const verifyOps = userTxs + consensus * (cfg.validators - 1);
    const signMs = (signOps * scheme.signUs) / 1000;
    const verifyMs = (verifyOps * scheme.verifyUs) / 1000;
    const authMibPerMin = (totalAuth * cfg.blocksPerMinute) / (1024 * 1024);

    return {
      userTxs,
      consensusMsgs: consensus,
      txAuthBytes: txAuth,
      consensusAuthBytes: consensusAuth,
      totalAuthBytesPerBlock: totalAuth,
      totalAuthMibPerMinute: authMibPerMin,
      estSignCpuMsPerBlock: signMs,
      estVerifyCpuMsPerBlock: verifyMs,
      estAuthCpuMsPerBlock: signMs + verifyMs,
    };
  }

  function blockTimeMs(blocksPerMinute) {
    return (60 / blocksPerMinute) * 1000;
  }

  /** CPU-only TPS loss: auth verify+sign time vs block interval */
  function cpuLossPct(authCpuMs, blockMs) {
    return Math.min(95, round1((100 * authCpuMs) / blockMs));
  }

  /** Block-size cap: auth payload that must fit in each block */
  function bandwidthLossPct(totalAuthBytes, blockAuthCapBytes) {
    if (totalAuthBytes <= blockAuthCapBytes) return 0;
    return Math.min(95, round1(100 * (1 - blockAuthCapBytes / totalAuthBytes)));
  }

  /** Network link cap: sustained auth bytes/sec vs validator link (Mbps) */
  function networkLossPct(totalAuthBytes, blocksPerMinute, networkMbps) {
    if (!networkMbps || networkMbps <= 0) return 0;
    const authBytesPerSec = (totalAuthBytes * blocksPerMinute) / 60;
    const capBytesPerSec = (networkMbps * 1_000_000) / 8;
    if (authBytesPerSec <= capBytesPerSec) return 0;
    return Math.min(95, round1(100 * (1 - capBytesPerSec / authBytesPerSec)));
  }

  function effectiveTps(baseTps, lossPct) {
    return Math.max(1, Math.round(baseTps * (1 - lossPct / 100)));
  }

  function computeSchemeTps(scheme, cfg, baseTps, blockAuthCapBytes, networkMbps) {
    const w = evaluateScheme(scheme, cfg);
    const blockMs = blockTimeMs(cfg.blocksPerMinute);
    const cpuLoss = cpuLossPct(w.estAuthCpuMsPerBlock, blockMs);
    const blockCapLoss = bandwidthLossPct(w.totalAuthBytesPerBlock, blockAuthCapBytes);
    const netLoss = networkLossPct(w.totalAuthBytesPerBlock, cfg.blocksPerMinute, networkMbps);
    const bwLoss = Math.max(blockCapLoss, netLoss);

    const cpuTps = effectiveTps(baseTps, cpuLoss);
    const bwTps = effectiveTps(baseTps, bwLoss);
    const combinedLoss = Math.max(cpuLoss, bwLoss);
    const combinedTps = Math.min(cpuTps, bwTps);
    const bottleneck =
      cpuLoss >= bwLoss
        ? bwLoss === 0 && cpuLoss === 0
          ? "none"
          : "cpu"
        : blockCapLoss >= netLoss
          ? "block cap"
          : "network";

    return {
      short_name: scheme.shortName,
      is_silmarils: scheme.isSilmarils,
      is_hybrid: false,
      base_tps: baseTps,
      auth_bytes_per_block: w.totalAuthBytesPerBlock,
      auth_cpu_ms_per_block: round1(w.estAuthCpuMsPerBlock),
      cpu_loss_pct: cpuLoss,
      bandwidth_loss_pct: bwLoss,
      block_cap_loss_pct: blockCapLoss,
      network_loss_pct: netLoss,
      cpu_effective_tps: cpuTps,
      bandwidth_effective_tps: bwTps,
      effective_tps: combinedTps,
      tps_loss_pct: combinedLoss,
      bottleneck,
    };
  }

  function buildComparison(cfg) {
    const dilithium2 = PRIMARY.find((s) => s.name.includes("Dilithium-2"));
    const schemes = PRIMARY.map((s) => {
      const workload = evaluateScheme(s, cfg);
      return {
        ...s,
        isPublicVerifier: s.isPublic,
        sigRatioVsDilithium2Pct: round1((100 * s.sigBytes) / dilithium2.sigBytes),
        workload: {
          total_auth_bytes_per_block: workload.totalAuthBytesPerBlock,
          total_auth_mib_per_minute: workload.totalAuthMibPerMinute,
          est_verify_cpu_ms_per_block: workload.estVerifyCpuMsPerBlock,
          est_auth_cpu_ms_per_block: workload.estAuthCpuMsPerBlock,
        },
      };
    });

    const sil = schemes.find((s) => s.isSilmarils);
    const dil = schemes.find((s) => s.name.includes("Dilithium-2"));
    const savings = Math.round(
      100 * (1 - sil.workload.total_auth_bytes_per_block / dil.workload.total_auth_bytes_per_block)
    );

    return {
      schemes,
      highlights: {
        sizeReductionFactor: round1(dilithium2.sigBytes / sil.sigBytes),
        authSavingsPctVsDilithium2: savings,
      },
    };
  }

  function buildTps(baseTps, cfg, blockAuthCapBytes, networkMbps) {
    const schemes = PRIMARY.map((s) =>
      computeSchemeTps(s, cfg, baseTps, blockAuthCapBytes, networkMbps)
    );

    const silScheme = PRIMARY.find((s) => s.isSilmarils);
    const silMetrics = evaluateScheme(silScheme, cfg);
    const hybridBlockCapLoss = bandwidthLossPct(
      silMetrics.totalAuthBytesPerBlock,
      blockAuthCapBytes
    );
    const hybridNetLoss = networkLossPct(
      silMetrics.totalAuthBytesPerBlock,
      cfg.blocksPerMinute,
      networkMbps
    );
    const hybridBwLoss = Math.max(hybridBlockCapLoss, hybridNetLoss);
    const hybridCpuTps = effectiveTps(baseTps, HYBRID_CPU_LOSS);
    const hybridBwTps = effectiveTps(baseTps, hybridBwLoss);
    const hybridCombinedLoss = Math.max(HYBRID_CPU_LOSS, hybridBwLoss);

    const hybrid_stack = {
      short_name: "SILMARILS Hybrid",
      is_silmarils: true,
      is_hybrid: true,
      base_tps: baseTps,
      cpu_loss_pct: HYBRID_CPU_LOSS,
      bandwidth_loss_pct: hybridBwLoss,
      cpu_effective_tps: hybridCpuTps,
      bandwidth_effective_tps: hybridBwTps,
      effective_tps: Math.min(hybridCpuTps, hybridBwTps),
      tps_loss_pct: hybridCombinedLoss,
      bottleneck: hybridBwLoss > HYBRID_CPU_LOSS ? "bandwidth" : "architecture (2%)",
      auth_bytes_per_block: silMetrics.totalAuthBytesPerBlock,
    };

    const retrofitEffective = effectiveTps(baseTps, RETROFIT_LOSS);
    const full_pq_retrofit = {
      short_name: "Full PQ retrofit",
      is_hybrid: false,
      effective_tps: retrofitEffective,
      tps_loss_pct: RETROFIT_LOSS,
      bottleneck: "industry benchmark",
      cpu_effective_tps: retrofitEffective,
      bandwidth_effective_tps: retrofitEffective,
    };

    return {
      base_tps: baseTps,
      block_auth_cap_bytes: blockAuthCapBytes,
      network_mbps: networkMbps,
      block_time_ms: round1(blockTimeMs(cfg.blocksPerMinute)),
      schemes,
      hybrid_stack,
      full_pq_retrofit,
      highlights: {
        hybrid_vs_retrofit_tps_gain_pct: round1(
          (100 * (hybrid_stack.effective_tps - retrofitEffective)) /
            Math.max(retrofitEffective, 1)
        ),
      },
    };
  }

  global.DemoModels = {
    PRIMARY,
    buildComparison,
    buildTps,
    evaluateScheme,
    defaultConfig: () => ({
      validators: 7,
      txPerBlock: 500,
      blocksPerMinute: 2,
      consensusRounds: 3,
      userTxRatio: 0.85,
    }),
    defaultBlockAuthCapBytes: 256 * 1024,
    defaultNetworkMbps: 100,
  };
})(window);
