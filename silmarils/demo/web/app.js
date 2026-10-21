const $ = (sel) => document.querySelector(sel);

let sizeChart;
let ledgerChart;
let tpsChart;
let cryptoKeys;

function debounce(fn, ms = 200) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function statusClass(ok) {
  return ok ? "ok" : "fail";
}

function statusText(ok) {
  return ok ? "PASS" : "FAIL";
}

function fmtBytes(n) {
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${n} B`;
}

function fmtTps(n) {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}k` : `${n}`;
}

function bottleneckTag(row) {
  const b = row.bottleneck || "—";
  if (b === "bandwidth" || b === "block cap" || b === "network") {
    return `<span class="tag-bottleneck tag-bottleneck--bw">${b}</span>`;
  }
  if (b === "cpu") {
    return `<span class="tag-bottleneck tag-bottleneck--cpu">${b}</span>`;
  }
  return `<span class="tag-bottleneck">${b}</span>`;
}

function ledgerConfigFromUi() {
  const base = DemoModels.defaultConfig();
  return {
    ...base,
    validators: +$("#validators").value,
    txPerBlock: +$("#tx-per-block").value,
    blocksPerMinute: +$("#blocks-per-minute").value,
  };
}

function tpsConfigFromUi() {
  return {
    ...ledgerConfigFromUi(),
    validators: +$("#tps-validators").value,
    txPerBlock: +$("#tps-tx-per-block").value,
    blocksPerMinute: +$("#blocks-per-minute").value,
  };
}

function tpsLimitsFromUi() {
  return {
    blockAuthCapBytes: +$("#block-auth-cap").value,
    networkMbps: +$("#network-mbps").value,
  };
}

function normalizeComparison(raw) {
  return {
    schemes: raw.schemes.map((s) => ({
      name: s.name,
      short_name: s.shortName,
      sig_bytes: s.sigBytes,
      is_silmarils: s.isSilmarils,
      is_public_verifier: s.isPublicVerifier,
      workload: {
        total_auth_bytes_per_block: s.workload.total_auth_bytes_per_block,
        total_auth_mib_per_minute: s.workload.total_auth_mib_per_minute,
        est_verify_cpu_ms_per_block: s.workload.est_verify_cpu_ms_per_block,
      },
    })),
    highlights: {
      size_reduction_factor: raw.highlights.sizeReductionFactor,
      auth_savings_pct_vs_dilithium2: raw.highlights.authSavingsPctVsDilithium2,
    },
  };
}

async function runLive(simulateOnly = false) {
  const { Silmarils, encodeMessage } = SilmarilsCrypto;
  const scheme = new Silmarils();
  if (!cryptoKeys) cryptoKeys = await scheme.keygen();
  const msg = encodeMessage($("#message-input").value);

  const t0 = performance.now();
  const real = await scheme.sign(msg, cryptoKeys);
  const signUs = (performance.now() - t0) * 1000;

  const t1 = performance.now();
  const realOk = await scheme.verify(msg, real, cryptoKeys);
  const verifyUs = (performance.now() - t1) * 1000;

  const sim = await scheme.simulate(msg, cryptoKeys);
  const simOk = await scheme.verify(msg, sim, cryptoKeys);
  const auditOk = scheme.auditVerify(real);

  const cells = $("#live-results").querySelectorAll(".result__value");
  cells[0].textContent = statusText(realOk);
  cells[0].className = `result__value ${statusClass(realOk)}`;
  cells[1].textContent = statusText(simOk);
  cells[1].className = `result__value ${statusClass(simOk)}`;
  cells[2].textContent = statusText(auditOk);
  cells[2].className = `result__value ${statusClass(auditOk)}`;
  cells[3].textContent = `${real.ledgerTranscriptBytes} B (σ+r)`;
  cells[3].className = "result__value";
  cells[4].textContent = `${signUs.toFixed(0)} / ${verifyUs.toFixed(0)} µs`;
  cells[4].className = "result__value";

  if (simulateOnly) {
    cells[0].textContent = "—";
    cells[0].className = "result__value muted";
  }
}

function chartColors(items) {
  return items.map((s) => (s.is_silmarils || s.is_hybrid ? "#38bdf8" : "#f87171"));
}

function updateCharts(data) {
  const labels = data.schemes.map((s) => s.short_name);
  const colors = chartColors(data.schemes);

  if (sizeChart) sizeChart.destroy();
  sizeChart = new Chart($("#chart-sizes"), {
    type: "bar",
    data: {
      labels,
      datasets: [{ data: data.schemes.map((s) => s.sig_bytes), backgroundColor: colors, borderRadius: 6 }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        y: { type: "logarithmic", ticks: { color: "#8b949e" }, grid: { color: "rgba(255,255,255,0.06)" } },
        x: { ticks: { color: "#8b949e" }, grid: { display: false } },
      },
    },
  });

  if (ledgerChart) ledgerChart.destroy();
  ledgerChart = new Chart($("#chart-ledger"), {
    type: "bar",
    data: {
      labels,
      datasets: [{
        data: data.schemes.map((s) => s.workload.total_auth_bytes_per_block),
        backgroundColor: colors,
        borderRadius: 6,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        y: { ticks: { color: "#8b949e", callback: (v) => fmtBytes(v) }, grid: { color: "rgba(255,255,255,0.06)" } },
        x: { ticks: { color: "#8b949e" }, grid: { display: false } },
      },
    },
  });
}

function updateTable(data) {
  const tbody = $("#compare-table tbody");
  tbody.innerHTML = "";
  for (const s of data.schemes) {
    const tr = document.createElement("tr");
    if (s.is_silmarils) tr.classList.add("highlight");
    tr.innerHTML = `
      <td>${s.name}</td>
      <td>${s.sig_bytes.toLocaleString()} B</td>
      <td>${s.is_public_verifier ? "Public" : "TDV"}</td>
      <td>${fmtBytes(s.workload.total_auth_bytes_per_block)}</td>
      <td>${s.workload.total_auth_mib_per_minute.toFixed(2)} MiB</td>
      <td>${s.workload.est_verify_cpu_ms_per_block.toFixed(1)} ms</td>
    `;
    tbody.appendChild(tr);
  }
}

function updateHighlights(data) {
  $("#stat-factor").textContent = `${data.highlights.size_reduction_factor}×`;
  $("#stat-savings").textContent = `${data.highlights.auth_savings_pct_vs_dilithium2}%`;
}

function refreshComparison() {
  const cfg = ledgerConfigFromUi();
  $("#out-validators").textContent = cfg.validators;
  $("#out-tx").textContent = cfg.txPerBlock;
  $("#out-bpm").textContent = cfg.blocksPerMinute.toFixed(1);

  const data = normalizeComparison(DemoModels.buildComparison(cfg));
  updateCharts(data);
  updateTable(data);
  updateHighlights(data);
}

function updateTpsBreakdownTable(rows) {
  const tbody = $("#tps-breakdown tbody");
  tbody.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    if (r.is_silmarils || r.is_hybrid) tr.classList.add("highlight");
    tr.innerHTML = `
      <td>${r.short_name}</td>
      <td>${fmtTps(r.cpu_effective_tps || r.effective_tps)}</td>
      <td>${r.cpu_loss_pct != null ? r.cpu_loss_pct + "%" : "—"}</td>
      <td>${fmtTps(r.bandwidth_effective_tps || r.effective_tps)}</td>
      <td>${r.bandwidth_loss_pct != null ? r.bandwidth_loss_pct + "%" : "—"}</td>
      <td><strong>${fmtTps(r.effective_tps)}</strong></td>
      <td>${bottleneckTag(r)}</td>
    `;
    tbody.appendChild(tr);
  }
}

function updateTpsChart(items) {
  const labels = items.map((i) => i.short_name);

  if (tpsChart) tpsChart.destroy();
  tpsChart = new Chart($("#chart-tps"), {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "CPU-limited TPS",
          data: items.map((i) => i.cpu_effective_tps ?? i.effective_tps),
          backgroundColor: "rgba(56, 189, 248, 0.45)",
          borderRadius: 4,
        },
        {
          label: "Bandwidth-limited TPS",
          data: items.map((i) => i.bandwidth_effective_tps ?? i.effective_tps),
          backgroundColor: "rgba(232, 176, 32, 0.55)",
          borderRadius: 4,
        },
        {
          label: "Combined (bottleneck)",
          data: items.map((i) => i.effective_tps),
          backgroundColor: items.map((i) =>
            i.is_hybrid || i.is_silmarils ? "#38bdf8" : "#f87171"
          ),
          borderRadius: 4,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        legend: { labels: { color: "#8b949e", boxWidth: 12 } },
      },
      scales: {
        y: { ticks: { color: "#8b949e" }, grid: { color: "rgba(255,255,255,0.06)" } },
        x: { ticks: { color: "#8b949e", maxRotation: 22 }, grid: { display: false } },
      },
    },
  });
}

function refreshTps() {
  const baseTps = +$("#base-tps").value;
  const cfg = tpsConfigFromUi();
  const limits = tpsLimitsFromUi();

  $("#out-base-tps").textContent = baseTps.toLocaleString();
  $("#out-tps-validators").textContent = cfg.validators;
  $("#out-tps-tx").textContent = cfg.txPerBlock;
  $("#out-block-cap").textContent = fmtBytes(limits.blockAuthCapBytes);
  $("#out-network-mbps").textContent = limits.networkMbps;

  const data = DemoModels.buildTps(
    baseTps,
    cfg,
    limits.blockAuthCapBytes,
    limits.networkMbps
  );

  const hybrid = data.hybrid_stack;
  const dil = data.schemes.find((s) => s.short_name.includes("Dilithium"));
  const sil = data.schemes.find((s) => s.is_silmarils);
  const retrofit = data.full_pq_retrofit;

  $("#tps-hybrid").textContent = `${fmtTps(hybrid.effective_tps)} TPS`;
  $("#tps-hybrid-loss").textContent = `combined ${hybrid.tps_loss_pct}% · ${hybrid.bottleneck}`;
  $("#tps-dilithium").textContent = `${fmtTps(dil.effective_tps)} TPS`;
  $("#tps-dilithium-loss").textContent = `combined ${dil.tps_loss_pct}% · bottleneck: ${dil.bottleneck}`;
  $("#tps-silmarils").textContent = `${fmtTps(sil.effective_tps)} TPS`;
  $("#tps-silmarils-loss").textContent = `combined ${sil.tps_loss_pct}% · bottleneck: ${sil.bottleneck}`;
  $("#tps-retrofit").textContent = `${fmtTps(retrofit.effective_tps)} TPS`;
  $("#tps-retrofit-loss").textContent = `${retrofit.tps_loss_pct}% · whole-chain PQ migration estimate`;

  $("#stat-tps-gain").textContent = `+${data.highlights.hybrid_vs_retrofit_tps_gain_pct}%`;

  const chartItems = [
    hybrid,
    sil,
    dil,
    ...data.schemes.filter((s) => s.short_name.includes("SPHINCS")),
    retrofit,
  ];

  updateTpsChart(chartItems);
  updateTpsBreakdownTable(chartItems);
}

function bindControls() {
  const debouncedCompare = debounce(refreshComparison);
  const debouncedTps = debounce(refreshTps);

  for (const id of ["validators", "tx-per-block", "blocks-per-minute"]) {
    $(`#${id}`).addEventListener("input", () => {
      debouncedCompare();
      debouncedTps();
    });
  }
  for (const id of ["base-tps", "tps-validators", "tps-tx-per-block", "block-auth-cap", "network-mbps"]) {
    $(`#${id}`).addEventListener("input", debouncedTps);
  }

  $("#btn-sign").addEventListener("click", () => runLive(false));
  $("#btn-simulate").addEventListener("click", () => runLive(true));
}

document.addEventListener("DOMContentLoaded", async () => {
  bindControls();
  refreshComparison();
  refreshTps();
  await runLive(false);
});
