/**
 * app.js - Frontend Controller for TLS Cryptographic Failures Demonstration
 * 23CSE331 Cryptography Case Study &bull; Amrita Vishwa Vidyapeetham
 */

let rc4ChartInstance = null;

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initSliders();
  initModal();
  initPresetChips();
  initKeyboardShortcuts();
  loadProjectInfo();
  bindActionButtons();
});

/* ================= TAB NAVIGATION ================= */
function initTabs() {
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      tabButtons.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetPane = document.getElementById(targetId);
      if (targetPane) {
        targetPane.classList.add("active");
      }

      // If user switches to RC4 tab and chart exists, ensure proper resize
      if (targetId === "tab-rc4" && rc4ChartInstance) {
        setTimeout(() => rc4ChartInstance.resize(), 100);
      }
    });
  });
}

/* ================= SLIDERS ================= */
function initSliders() {
  const rc4Slider = document.getElementById("rc4-sessions");
  const rc4Val = document.getElementById("rc4-sessions-val");
  if (rc4Slider && rc4Val) {
    rc4Slider.addEventListener("input", () => {
      rc4Val.textContent = Number(rc4Slider.value).toLocaleString();
    });
  }

  const dhSlider = document.getElementById("dh-bits");
  const dhVal = document.getElementById("dh-bits-val");
  if (dhSlider && dhVal) {
    dhSlider.addEventListener("input", () => {
      dhVal.textContent = dhSlider.value;
    });
  }
}

/* ================= MODAL & ESCAPE KEY ================= */
function initModal() {
  const modal = document.getElementById("team-modal");
  const openBtn = document.getElementById("btn-team-modal");
  const closeBtn = document.getElementById("modal-close");

  if (openBtn && modal) {
    openBtn.addEventListener("click", () => modal.classList.remove("hidden"));
  }
  if (closeBtn && modal) {
    closeBtn.addEventListener("click", () => modal.classList.add("hidden"));
  }
  window.addEventListener("click", (e) => {
    if (e.target === modal) modal.classList.add("hidden");
  });
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal && !modal.classList.contains("hidden")) {
      modal.classList.add("hidden");
    }
  });
}

/* ================= PRESET CHIPS ================= */
function initPresetChips() {
  const chips = document.querySelectorAll(".preset-chip");
  chips.forEach(chip => {
    chip.addEventListener("click", () => {
      const host = chip.getAttribute("data-host");
      const port = chip.getAttribute("data-port") || "443";
      const hostInput = document.getElementById("remote-host");
      const portInput = document.getElementById("remote-port");
      if (hostInput) hostInput.value = host;
      if (portInput) portInput.value = port;
      runRemoteAudit();
    });
  });
}

/* ================= KEYBOARD SHORTCUTS (ENTER KEY) ================= */
function initKeyboardShortcuts() {
  bindEnterKey("remote-host", runRemoteAudit);
  bindEnterKey("remote-port", runRemoteAudit);
  bindEnterKey("oracle-message", runPaddingOracleAttack);
  bindEnterKey("rc4-secret", runRC4Attack);
  bindEnterKey("dh-message", runWeakDHAttack);
  bindEnterKey("fs-message", runForwardSecrecyAttack);
}

function bindEnterKey(elementId, callback) {
  const el = document.getElementById(elementId);
  if (el) {
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        callback();
      }
    });
  }
}

/* ================= UI NOTIFICATIONS ================= */
function showToast(message, type = "error") {
  const oldToast = document.querySelector(".toast-notice");
  if (oldToast) oldToast.remove();

  const toast = document.createElement("div");
  toast.className = `toast-notice ${type === "error" ? "toast-error" : "toast-success"}`;
  toast.innerHTML = `
    <span>${type === "error" ? "⚠️" : "✅"}</span>
    <span>${escapeHtml(message)}</span>
  `;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.transition = "opacity 0.3s ease, transform 0.3s ease";
    toast.style.opacity = "0";
    toast.style.transform = "translateY(10px)";
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}

/* ================= INITIAL INFO LOADING ================= */
async function loadProjectInfo() {
  try {
    const res = await fetch("/api/info");
    if (!res.ok) throw new Error("Backend not responding");
    const data = await res.json();

    const hostLabel = window.location.host || "127.0.0.1:8080";
    document.getElementById("api-status").textContent = `API Connected (${hostLabel})`;

    // Populate Matrix Table in Tab 6
    const matrixBody = document.getElementById("matrix-table-body");
    if (matrixBody && data.matrix) {
      matrixBody.innerHTML = data.matrix.map(row => `
        <tr>
          <td><strong>${escapeHtml(row.attack)}</strong></td>
          <td class="text-red">${escapeHtml(row.tls12)}</td>
          <td class="text-green">${escapeHtml(row.tls13)}</td>
          <td><span class="badge badge-purple">${escapeHtml(row.cve)}</span></td>
        </tr>
      `).join("");
    }

    // Populate Comprehensive CVE & Attack Model Cards in Tab 6
    const cveContainer = document.getElementById("cve-cards-container");
    if (cveContainer && data.models && data.incidents) {
      cveContainer.innerHTML = Object.entries(data.models).map(([key, m]) => {
        const cve = data.incidents[key] || "RFC Standard";
        return `
          <div class="cve-card">
            <h4>${escapeHtml(m.name)}</h4>
            <div class="cve-tag">${escapeHtml(cve)}</div>
            <p><strong>Threat Model:</strong> ${escapeHtml(m.adversary)}</p>
            <p style="margin-top: 6px;"><strong>Attacker Knowledge:</strong> ${escapeHtml(m.knowledge)}</p>
            <p style="margin-top: 6px;"><strong>Adversary Capability:</strong> ${escapeHtml(m.capability)}</p>
            <p style="margin-top: 6px;"><strong>Primary Goal:</strong> ${escapeHtml(m.goal)}</p>
            <p style="margin-top: 6px; font-size: 12.5px; color: #9ca3af;"><strong>Core Assumption:</strong> ${escapeHtml(m.assumption)}</p>
          </div>
        `;
      }).join("");
    }
  } catch (err) {
    const status = document.getElementById("api-status");
    if (status) {
      status.textContent = "API Disconnected (Offline)";
      status.style.color = "#ef4444";
    }
  }
}

/* ================= ACTION BUTTONS BINDING ================= */
function bindActionButtons() {
  const btnLabAudit = document.getElementById("btn-run-lab-audit");
  if (btnLabAudit) btnLabAudit.addEventListener("click", runLabAudit);

  const btnRemoteAudit = document.getElementById("btn-run-remote-audit");
  if (btnRemoteAudit) btnRemoteAudit.addEventListener("click", runRemoteAudit);

  const btnOracle = document.getElementById("btn-run-oracle");
  if (btnOracle) btnOracle.addEventListener("click", runPaddingOracleAttack);

  const btnRC4 = document.getElementById("btn-run-rc4");
  if (btnRC4) btnRC4.addEventListener("click", runRC4Attack);

  const btnDH = document.getElementById("btn-run-dh");
  if (btnDH) btnDH.addEventListener("click", runWeakDHAttack);

  const btnFS = document.getElementById("btn-run-fs");
  if (btnFS) btnFS.addEventListener("click", runForwardSecrecyAttack);
}

/* ================= STAGE 1: SERVER AUDITING ================= */
async function runLabAudit() {
  const btn = document.getElementById("btn-run-lab-audit");
  const spinner = document.getElementById("lab-audit-spinner");
  const container = document.getElementById("audit-results-container");

  btn.disabled = true;
  spinner.classList.remove("hidden");

  try {
    const res = await fetch("/api/audit-lab", { method: "POST" });
    const data = await res.json();

    if (data.success && data.details) {
      const vuln = data.details.VULNERABLE;
      const hard = data.details.HARDENED;

      container.innerHTML = `
        <div class="audit-grid">
          <!-- Vulnerable Server -->
          <div class="audit-card">
            <div class="audit-top">
              <div>
                <h3>Vulnerable Lab Server</h3>
                <span class="badge badge-red">Port ${vuln.port || 9441} &bull; Legacy</span>
              </div>
              <div class="grade-badge grade-${vuln.grade}">${vuln.grade}</div>
            </div>
            <p><strong>Negotiated:</strong> <code>${escapeHtml(vuln.info.negotiated)}</code></p>
            <div class="badge-row">
              <strong>Protocols:</strong>
              ${formatProtocols(vuln.info.protocols)}
            </div>
            <div class="badge-row">
              <strong>Weak Ciphers:</strong>
              ${formatWeakCiphers(vuln.info.weak_ciphers)}
            </div>
            <ul class="findings-list">
              ${vuln.findings.map(f => renderFindingItem(f)).join("")}
            </ul>
          </div>

          <!-- Hardened Server -->
          <div class="audit-card">
            <div class="audit-top">
              <div>
                <h3>Hardened Lab Server</h3>
                <span class="badge badge-green">Port ${hard.port || 9442} &bull; Modern</span>
              </div>
              <div class="grade-badge grade-${hard.grade}">${hard.grade}</div>
            </div>
            <p><strong>Negotiated:</strong> <code>${escapeHtml(hard.info.negotiated)}</code></p>
            <div class="badge-row">
              <strong>Protocols:</strong>
              ${formatProtocols(hard.info.protocols)}
            </div>
            <div class="badge-row">
              <strong>Weak Ciphers:</strong>
              ${formatWeakCiphers(hard.info.weak_ciphers)}
            </div>
            <ul class="findings-list">
              ${hard.findings.map(f => renderFindingItem(f)).join("")}
            </ul>
          </div>
        </div>
      `;
    }
  } catch (err) {
    showToast("Lab audit simulation failed: " + err.message, "error");
  } finally {
    btn.disabled = false;
    spinner.classList.add("hidden");
  }
}

async function runRemoteAudit() {
  const host = document.getElementById("remote-host").value.trim();
  const port = parseInt(document.getElementById("remote-port").value, 10) || 443;
  const btn = document.getElementById("btn-run-remote-audit");
  const spinner = document.getElementById("remote-audit-spinner");
  const container = document.getElementById("audit-results-container");

  if (!host) {
    showToast("Please enter a valid hostname to audit.", "error");
    return;
  }

  btn.disabled = true;
  spinner.classList.remove("hidden");

  try {
    const res = await fetch("/api/audit-host", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host, port })
    });
    const data = await res.json();

    if (!data.success) {
      showToast("Remote audit error: " + (data.error || "Handshake failed"), "error");
      return;
    }

    container.innerHTML = `
      <div class="audit-card" style="margin-top: 20px;">
        <div class="audit-top">
          <div>
            <h3>Audit Report: ${escapeHtml(data.host)}:${data.port}</h3>
            <span class="badge badge-blue">Remote Target</span>
          </div>
          <div class="grade-badge grade-${data.grade}">${data.grade}</div>
        </div>
        <p><strong>Negotiated:</strong> <code>${escapeHtml(data.info.negotiated)}</code></p>
        <div class="badge-row">
          <strong>Protocols:</strong>
          ${formatProtocols(data.info.protocols)}
        </div>
        <div class="badge-row">
          <strong>Weak Ciphers:</strong>
          ${formatWeakCiphers(data.info.weak_ciphers)}
        </div>
        <ul class="findings-list">
          ${data.findings.map(f => renderFindingItem(f)).join("")}
        </ul>
      </div>
    `;
  } catch (err) {
    showToast("Connection error auditing remote host: " + err.message, "error");
  } finally {
    btn.disabled = false;
    spinner.classList.add("hidden");
  }
}

function renderFindingItem(f) {
  const [sev, category, desc] = f;
  return `
    <li class="finding-item">
      <span class="finding-sev sev-${sev}">${sev}</span>
      <div>
        <strong>${escapeHtml(category)}:</strong> ${escapeHtml(desc)}
      </div>
    </li>
  `;
}

function formatProtocols(obj) {
  if (!obj) return "<span class='badge badge-purple'>N/A</span>";
  return Object.entries(obj).map(([proto, status]) => {
    let badgeClass = "badge-purple";
    if (status === "accepted") {
      if (proto === "TLSv1.3") badgeClass = "badge-green";
      else if (proto === "TLSv1.2") badgeClass = "badge-blue";
      else badgeClass = "badge-red"; // TLS 1.0 or 1.1 accepted = insecure
    } else {
      if (proto === "TLSv1.0" || proto === "TLSv1.1") badgeClass = "badge-green"; // properly rejected legacy
      else badgeClass = "badge-yellow";
    }
    return `<span class="badge ${badgeClass}">${proto}: ${status}</span>`;
  }).join(" ");
}

function formatWeakCiphers(obj) {
  if (!obj) return "<span class='badge badge-purple'>N/A</span>";
  return Object.entries(obj).map(([cipher, status]) => {
    const badgeClass = status === "accepted" ? "badge-red" : "badge-green";
    return `<span class="badge ${badgeClass}">${cipher}: ${status}</span>`;
  }).join(" ");
}

/* ================= STAGE 2a: PADDING ORACLE ================= */
async function runPaddingOracleAttack() {
  const message = document.getElementById("oracle-message").value;
  const btn = document.getElementById("btn-run-oracle");
  const spinner = document.getElementById("oracle-spinner");
  const output = document.getElementById("oracle-output");

  if (!message) {
    showToast("Please enter a target message or session cookie.", "error");
    return;
  }

  btn.disabled = true;
  spinner.classList.remove("hidden");
  output.classList.add("hidden");

  try {
    const res = await fetch("/api/attack/padding-oracle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message })
    });
    const data = await res.json();

    if (data.error) {
      showToast("Oracle attack error: " + data.error, "error");
      return;
    }

    document.getElementById("oracle-status").textContent = data.success ? "100% RECOVERED" : "PARTIAL";
    document.getElementById("oracle-queries").textContent = data.queries.toLocaleString();
    document.getElementById("oracle-time").textContent = `${data.time_sec} s`;
    document.getElementById("oracle-blocks").textContent = `${data.num_blocks} blocks (${data.num_blocks * 16} bytes)`;
    document.getElementById("oracle-recovered-text").textContent = data.recovered;

    document.getElementById("aead-tested").textContent = data.aead_tested;
    document.getElementById("aead-accepted").textContent = `${data.aead_accepted} (InvalidTag)`;

    output.classList.remove("hidden");
  } catch (err) {
    showToast("Padding oracle request failed: " + err.message, "error");
  } finally {
    btn.disabled = false;
    spinner.classList.add("hidden");
  }
}

/* ================= STAGE 2b: RC4 BIAS ================= */
async function runRC4Attack() {
  const secret = document.getElementById("rc4-secret").value;
  const sessions = parseInt(document.getElementById("rc4-sessions").value, 10);
  const btn = document.getElementById("btn-run-rc4");
  const spinner = document.getElementById("rc4-spinner");
  const output = document.getElementById("rc4-output");

  if (!secret) {
    showToast("Please enter a secret string for the RC4 simulation.", "error");
    return;
  }

  btn.disabled = true;
  spinner.classList.remove("hidden");
  output.classList.add("hidden");

  try {
    const res = await fetch("/api/attack/rc4", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret, sessions })
    });
    const data = await res.json();

    if (data.error) {
      showToast("RC4 attack error: " + data.error, "error");
      return;
    }

    document.getElementById("rc4-guess-char").textContent = `'${data.guess_char}'`;
    document.getElementById("rc4-match-sub").textContent = data.success
      ? `Matches target '${data.target_char}'!`
      : `Target was '${data.target_char}' (needs more sessions)`;
    document.getElementById("rc4-match-sub").className = data.success ? "metric-sub text-green" : "metric-sub text-orange";

    document.getElementById("rc4-measured-p0").textContent = `${data.measured_p0_pct}%`;
    document.getElementById("rc4-ideal-p0").textContent = `${data.ideal_p0_pct}%`;
    document.getElementById("rc4-time").textContent = `${data.time_sec} s`;
    document.getElementById("rc4-sessions-count").textContent = `${data.sessions.toLocaleString()} random keys`;

    // Candidate ranking table
    const candRows = document.getElementById("rc4-candidate-rows");
    candRows.innerHTML = data.top_candidates.map((c, idx) => {
      const isMatch = c.char === data.target_char;
      return `
        <tr style="${isMatch ? 'background: rgba(16, 185, 129, 0.08);' : ''}">
          <td><strong>#${idx + 1}</strong></td>
          <td><code>0x${c.byte.toString(16).padStart(2, '0').toUpperCase()}</code></td>
          <td><strong>'${escapeHtml(c.char)}'</strong> ${isMatch ? '<span class="badge badge-green">TARGET</span>' : ''}</td>
          <td>${c.count.toLocaleString()}</td>
          <td><span class="badge ${idx === 0 ? 'badge-green' : 'badge-purple'}">${((c.count / data.sessions) * 100).toFixed(3)}%</span></td>
        </tr>
      `;
    }).join("");

    output.classList.remove("hidden");

    // Render Chart
    renderRC4Chart(data.z2_counts, data.sessions);
  } catch (err) {
    showToast("RC4 attack request failed: " + err.message, "error");
  } finally {
    btn.disabled = false;
    spinner.classList.add("hidden");
  }
}

function renderRC4Chart(counts, sessions) {
  const ctx = document.getElementById("rc4Chart");
  if (!ctx) return;

  const probs = counts.map(c => c / sessions);
  const labels = Array.from({ length: 256 }, (_, i) => i);
  const idealVal = 1 / 256;

  if (typeof Chart !== "undefined") {
    if (rc4ChartInstance) {
      rc4ChartInstance.destroy();
    }

    rc4ChartInstance = new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [
          {
            type: "line",
            label: "Ideal Uniform (1/256 ≈ 0.391%)",
            data: Array(256).fill(idealVal),
            borderColor: "#ff3366",
            borderWidth: 2,
            borderDash: [5, 5],
            pointRadius: 0,
            pointHoverRadius: 0,
            fill: false,
            order: 1
          },
          {
            type: "bar",
            label: "Measured P(Z2 = v)",
            data: probs,
            backgroundColor: probs.map((_, i) => i === 0 ? "#ff0055" : "rgba(0, 242, 254, 0.6)"),
            borderColor: probs.map((_, i) => i === 0 ? "#ff0055" : "#00f2fe"),
            borderWidth: 1,
            barPercentage: 1.0,
            categoryPercentage: 1.0,
            order: 2
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                if (ctx.dataset.type === "line") {
                  return `Ideal Uniform: ${(ctx.parsed.y * 100).toFixed(3)}%`;
                }
                const hex = `0x${Number(ctx.label).toString(16).padStart(2, '0').toUpperCase()}`;
                return `Byte ${hex} (${ctx.label}): ${(ctx.parsed.y * 100).toFixed(4)}%`;
              }
            }
          }
        },
        scales: {
          x: {
            title: { display: true, text: "Byte value v (0 to 255)", color: "#9ca3af" },
            ticks: { color: "#6b7280", maxTicksLimit: 16 }
          },
          y: {
            title: { display: true, text: "Probability", color: "#9ca3af" },
            ticks: { color: "#6b7280" }
          }
        }
      }
    });
  } else {
    // Pure HTML5 Canvas 2D Fallback if Chart.js CDN is unreachable
    renderCanvasFallback(ctx, probs, idealVal);
  }
}

function renderCanvasFallback(canvas, probs, idealVal) {
  const ctx = canvas.getContext("2d");
  const w = canvas.width = canvas.parentElement.clientWidth || 800;
  const h = canvas.height = 280;

  ctx.clearRect(0, 0, w, h);
  const maxP = Math.max(...probs, idealVal * 2.2);
  const barW = w / 256;

  for (let i = 0; i < 256; i++) {
    const barH = (probs[i] / maxP) * (h - 40);
    ctx.fillStyle = (i === 0) ? "#ff0055" : "#00f2fe";
    ctx.fillRect(i * barW, h - barH - 20, Math.max(1, barW), barH);
  }

  // Draw ideal line
  const idealY = h - (idealVal / maxP) * (h - 40) - 20;
  ctx.strokeStyle = "#ff3366";
  ctx.setLineDash([4, 4]);
  ctx.beginPath();
  ctx.moveTo(0, idealY);
  ctx.lineTo(w, idealY);
  ctx.stroke();
  ctx.setLineDash([]);
}

/* ================= STAGE 2c: WEAK DIFFIE-HELLMAN ================= */
async function runWeakDHAttack() {
  const message = document.getElementById("dh-message").value;
  const bits = parseInt(document.getElementById("dh-bits").value, 10);
  const btn = document.getElementById("btn-run-dh");
  const spinner = document.getElementById("dh-spinner");
  const output = document.getElementById("dh-output");

  btn.disabled = true;
  spinner.classList.remove("hidden");
  output.classList.add("hidden");

  try {
    const res = await fetch("/api/attack/weak-dh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, bits })
    });
    const data = await res.json();

    if (data.error) {
      showToast("Weak DH attack error: " + data.error, "error");
      return;
    }

    document.getElementById("dh-status").textContent = data.success ? "COMPROMISED" : "FAILED";
    document.getElementById("dh-bits-metric").textContent = `${data.bits} bits`;
    document.getElementById("dh-time").textContent = `${data.time_sec} s`;
    document.getElementById("dh-complexity").textContent = `~2^${Math.floor(data.bits / 2)} operations (BSGS)`;

    document.getElementById("dh-public-params").innerHTML = `
Prime p       = ${escapeHtml(data.prime_p)} (${data.bits}-bit export prime)
Base g        = ${data.base_g}
Alice Pub A   = ${escapeHtml(data.alice_pub_A)}
Bob Pub B     = ${escapeHtml(data.bob_pub_B)}
Ciphertext    = ${escapeHtml(data.ciphertext.slice(0, 64))}...
Eve Solved x  = ${escapeHtml(data.solved_x)} via Baby-Step Giant-Step in ${data.time_sec}s
    `.trim();

    document.getElementById("dh-recovered-text").textContent = data.recovered;

    output.classList.remove("hidden");
  } catch (err) {
    showToast("Weak DH request failed: " + err.message, "error");
  } finally {
    btn.disabled = false;
    spinner.classList.add("hidden");
  }
}

/* ================= STAGE 2d: FORWARD SECRECY ================= */
async function runForwardSecrecyAttack() {
  const message = document.getElementById("fs-message").value;
  const btn = document.getElementById("btn-run-fs");
  const spinner = document.getElementById("fs-spinner");
  const output = document.getElementById("fs-output");

  btn.disabled = true;
  spinner.classList.remove("hidden");
  output.classList.add("hidden");

  try {
    const res = await fetch("/api/attack/forward-secrecy", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message })
    });
    const data = await res.json();

    if (data.error) {
      showToast("Forward secrecy simulation error: " + data.error, "error");
      return;
    }

    const ctSnippetA = data.session_a_ct ? `${data.session_a_ct.slice(0, 48)}...` : "[Encrypted]";
    const ctSnippetB = data.session_b_ct ? `${data.session_b_ct.slice(0, 48)}...` : "[Encrypted]";

    document.getElementById("fs-session-a-text").textContent = 
      `Decrypted Plaintext: "${data.session_a_decrypted}"\nRecorded Ciphertext: ${ctSnippetA}\nStatus: Static RSA private key compromised; all past sessions decrypted.`;

    document.getElementById("fs-session-b-text").textContent = 
      `Decryption Attempt: REJECTED (InvalidTag exception)\nRecorded Ciphertext: ${ctSnippetB}\nStatus: Ephemeral keys destroyed after handshake. Past traffic remains mathematically secure.`;

    output.classList.remove("hidden");
  } catch (err) {
    showToast("Forward secrecy request failed: " + err.message, "error");
  } finally {
    btn.disabled = false;
    spinner.classList.add("hidden");
  }
}

/* Utility to safely escape HTML */
function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
