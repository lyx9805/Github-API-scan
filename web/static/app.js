let currentPage = 1;
let currentPages = 1;
let currentPageSize = 20;
let logEventSource = null;
let logsPaused = false;

/* ════ Routing ════ */
const views = ["dashboard", "keys", "config", "logs"];

function navigateTo(viewName) {
  views.forEach(v => {
    document.getElementById("view-" + v).classList.toggle("active", v === viewName);
    document.querySelector(`.nav-item[data-view="${v}"]`)?.classList.toggle("active", v === viewName);
  });
}

document.querySelectorAll(".nav-item").forEach(el => {
  el.addEventListener("click", e => {
    e.preventDefault();
    navigateTo(el.dataset.view);
    if (el.dataset.view === "config") loadConfig();
  });
});

/* ════ Helpers ════ */
async function requestJson(url, options = {}) {
  const r = await fetch(url, { credentials: "include", headers: { "Content-Type": "application/json", ...(options.headers || {}) }, ...options });
  if (r.status === 401) { showLogin(); throw new Error("Unauthorized"); }
  const data = await r.json();
  if (!r.ok) throw new Error(data.detail || "HTTP " + r.status);
  return data;
}

function showLogin() {
  document.getElementById("loginView").classList.remove("hidden");
  document.getElementById("appView").classList.add("hidden");
  if (logEventSource) { logEventSource.close(); logEventSource = null; }
}

function showApp(username) {
  document.getElementById("loginView").classList.add("hidden");
  document.getElementById("appView").classList.remove("hidden");
  document.getElementById("currentUser").textContent = username;
}

function badge(status, extra) {
  return '<span class="badge ' + status + " " + (extra || "") + '">' + status + "</span>";
}

function esc(s) { return String(s || "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;"); }

/* ════ Dashboard Stats ════ */
async function loadStats() {
  const s = await requestJson("/api/stats");
  const r = s.runtime || {};
  document.getElementById("statValid").textContent = s.valid_total ?? "--";
  document.getElementById("statTotal").textContent = r.found_keys ?? s.total ?? "--";
  document.getElementById("statScanned").textContent = r.scanned_files ?? "--";
  document.getElementById("statHighValue").textContent = s.high_value ?? "--";
  document.getElementById("statStatus").textContent = r.is_running ? "Active" : "Stopped";
  document.getElementById("statQueue").textContent = r.queue_size ?? "--";

  /* Status chart */
  const st = s.statuses || {};
  const statusHtml = Object.entries(st).filter(([k]) => k !== "total").map(([k, v]) =>
    '<div class="chart-row"><span>' + k + '</span><span class="num">' + v + "</span></div>"
  ).join("");
  document.getElementById("statusChart").innerHTML = statusHtml || '<div class="chart-row muted">No data</div>';

  /* Platform chart */
  const pl = s.platforms || {};
  const platHtml = Object.entries(pl).map(([k, v]) =>
    '<div class="chart-row"><span>' + esc(k) + '</span><span class="num">' + v + "</span></div>"
  ).join("");
  document.getElementById("platformChart").innerHTML = platHtml || '<div class="chart-row muted">No data</div>';

  /* Daily chart */
  const daily = s.daily || [];
  const maxD = Math.max(...daily.map(d => d.count), 1);
  const dailyHtml = daily.map(d =>
    '<div class="bar-row"><span class="muted">' + esc(d.day) + '</span><div class="bar-track"><div class="bar-fill" style="width:' + (d.count / maxD * 100) + '%"></div></div><span>' + d.count + "</span></div>"
  ).join("");
  document.getElementById("dailyChart").innerHTML = dailyHtml || '<div class="muted">No trend data</div>';

  /* Token quota */
  const q = s.github_quota || [];
  const quotaHtml = q.map(item => {
    if (!item.ok) return '<div class="quota-card"><span class="muted">Token ' + item.token_index + ": " + esc(item.error || "N/A") + "</span></div>";
    return '<div class="quota-card"><div class="chart-row"><strong>' + esc(item.login || "Token " + item.token_index) + '</strong><span>' + (item.code_search_remaining ?? "--") + "/" + (item.code_search_limit ?? "--") + " reset " + (item.code_search_reset_bj || "--") + '</span></div><div class="chart-row"><span class="muted">Health ' + Number(item.health_score ?? 100).toFixed(1) + "</span><span class=\"muted\">OK " + (item.success_count || 0) + " Err " + (item.failure_count || 0) + " Rate " + (item.rate_limit_count || 0) + "</span></div></div>";
  }).join("");
  document.getElementById("quotaStatus").innerHTML = quotaHtml || '<div class="chart-row muted">No token data</div>';

  /* Proxy pool */
  const pp = s.proxy_pool || {};
  if (!pp.enabled) {
    document.getElementById("proxyPoolStatus").innerHTML = '<div class="chart-row muted">Proxy pool disabled</div>';
  } else {
    const top = (pp.proxies || []).slice(0, 8);
    document.getElementById("proxyPoolStatus").innerHTML = '<div class="chart-row"><strong>Healthy ' + (pp.healthy || 0) + "/" + (pp.total || 0) + '</strong><span class="muted">Unhealthy ' + (pp.unhealthy || 0) + "</span></div>" +
      top.map(p => '<div class="chart-row"><span>' + esc(p.url || "") + '</span><span class="muted">score ' + Number(p.health_score || 0).toFixed(1) + "</span></div>").join("");
  }

  /* Query quality */
  const qq = r.query_quality || s.query_quality || {};
  const qqEntries = Object.entries(qq);
  document.getElementById("queryQuality").innerHTML = qqEntries.length
    ? qqEntries.map(([k, v]) => '<div class="chart-row"><span>' + esc(k) + '</span><span class="num">' + v + "</span></div>").join("")
    : '<div class="chart-row muted">No quality data</div>';
}

/* ════ Keys Table ════ */
async function loadKeys(page) {
  page = page || currentPage;
  currentPageSize = Number(document.getElementById("pageSizeSelect").value);
  const status = document.getElementById("statusFilter").value;
  const platform = document.getElementById("platformFilter").value.trim();
  const params = new URLSearchParams({ page: String(page), page_size: String(currentPageSize) });
  if (status) params.set("status", status);
  if (platform) params.set("platform", platform);
  const data = await requestJson("/api/keys?" + params.toString());
  currentPage = data.page;
  currentPages = Math.max(data.pages || 1, 1);
  document.getElementById("keysMeta").textContent = "Total " + data.total;
  document.getElementById("pageInfo").textContent = data.page + " / " + currentPages;
  document.getElementById("prevPageBtn").disabled = data.page <= 1;
  document.getElementById("nextPageBtn").disabled = data.page >= currentPages;
  document.getElementById("keysTableBody").innerHTML = data.items.map(item =>
    "<tr><td>" + esc(item.platform) + '</td><td title="' + esc(item.base_url) + '">' + esc(item.api_key_masked) + (item.is_high_value ? ' <span class="badge high">HIGH</span>' : "") + '</td><td>' + badge(item.status) + '<div class="muted">' + esc(item.balance || "-") + '</div></td><td>' + (item.source_url ? '<a href="' + esc(item.source_url) + '" target="_blank" rel="noreferrer">source</a>' : "-") + '</td><td>' + esc(item.model_tier || "-") + '</td><td>' + esc(item.found_time || "-") + "</td></tr>"
  ).join("") || '<tr><td colspan="6" class="muted">No keys found</td></tr>';
}

/* ════ Config ════ */
async function loadConfig() {
  try {
    const cfg = await requestJson("/api/config");
    document.getElementById("cfgProxyUrl").value = cfg.proxy_url || "";
    document.getElementById("cfgEnvProxyUrl").value = cfg.env_proxy_url || "(not set)";
    document.getElementById("cfgProviders").value = (cfg.enabled_providers || []).join(", ");
    document.getElementById("cfgKeywords").value = (cfg.search_keywords || []).join(",\n");
    document.getElementById("cfgThreads").value = cfg.consumer_threads || 20;
    document.getElementById("cfgTimeout").value = cfg.request_timeout || 15;
    document.getElementById("cfgContextWindow").value = cfg.context_window || 10;
    document.getElementById("cfgConcurrency").value = cfg.max_concurrency || 100;
    document.getElementById("cfgRedisUrl").value = cfg.redis_url || "";
    document.getElementById("cfgCircuitBreaker").checked = cfg.circuit_breaker_enabled !== false;
    const tokenHtml = (cfg.github_tokens_masked || []).map(t => '<span class="token-badge">' + esc(t) + "</span>").join("") || '<span class="muted">No tokens configured (set GITHUB_TOKENS env)</span>';
    document.getElementById("cfgTokens").innerHTML = tokenHtml;
  } catch (e) {
    console.error("loadConfig error", e);
  }
}

async function saveConfig() {
  const btn = document.getElementById("configSaveBtn");
  const result = document.getElementById("configSaveResult");
  btn.disabled = true;
  btn.textContent = "Saving...";
  result.className = "config-result";
  try {
    const proxy = document.getElementById("cfgProxyUrl").value.trim();
    const providers = document.getElementById("cfgProviders").value.split(",").map(s => s.trim()).filter(Boolean);
    const kwText = document.getElementById("cfgKeywords").value;
    const keywords = kwText.split(/[,\n]+/).map(s => s.trim()).filter(Boolean);
    const payload = {
      proxy_url: proxy,
      enabled_providers: providers,
      search_keywords: keywords,
      consumer_threads: parseInt(document.getElementById("cfgThreads").value) || 20,
      request_timeout: parseInt(document.getElementById("cfgTimeout").value) || 15,
      context_window: parseInt(document.getElementById("cfgContextWindow").value) || 10,
      max_concurrency: parseInt(document.getElementById("cfgConcurrency").value) || 100,
      redis_url: document.getElementById("cfgRedisUrl").value.trim(),
      circuit_breaker_enabled: document.getElementById("cfgCircuitBreaker").checked,
    };
    const res = await requestJson("/api/config/update", { method: "POST", body: JSON.stringify(payload) });
    if (res.ok) {
      result.className = "config-result ok";
      result.textContent = res.message || "Configuration saved successfully";
    } else {
      result.className = "config-result err";
      result.textContent = res.message || "Save failed";
    }
  } catch (e) {
    result.className = "config-result err";
    result.textContent = "Error: " + e.message;
  }
  btn.disabled = false;
  btn.textContent = "Save Config";
}

/* ════ Logs ════ */
async function loadRecentLogs() {
  const data = await requestJson("/api/logs?lines=120");
  const out = document.getElementById("logOutput");
  out.textContent = data.lines.join("\n");
  out.scrollTop = out.scrollHeight;
  document.getElementById("logCount").textContent = data.lines.length + " lines";
}

function appendLogLine(line) {
  const out = document.getElementById("logOutput");
  out.textContent += "\n" + line;
  out.scrollTop = out.scrollHeight;
  const lines = out.textContent.split("\n");
  if (lines.length > 800) out.textContent = lines.slice(-800).join("\n");
}

function startLogStream() {
  if (logEventSource) logEventSource.close();
  logEventSource = new EventSource("/api/logs/stream", { withCredentials: true });
  logEventSource.onmessage = e => {
    if (logsPaused) return;
    const p = JSON.parse(e.data);
    appendLogLine(p.line);
  };
  logEventSource.onerror = () => {
    logEventSource.close();
    logEventSource = null;
    setTimeout(() => { if (!logsPaused) startLogStream(); }, 5000);
  };
}

async function refreshAll() {
  await Promise.all([loadStats(), loadKeys(currentPage)]);
}

async function bootstrap() {
  try {
    const me = await requestJson("/api/me");
    showApp(me.username);
    await refreshAll();
    startLogStream();
  } catch { showLogin(); }
}

/* ════ Event Bindings ════ */
document.getElementById("loginForm").addEventListener("submit", async e => {
  e.preventDefault();
  const username = document.getElementById("usernameInput").value.trim();
  const password = document.getElementById("passwordInput").value;
  const err = document.getElementById("loginError");
  err.textContent = "";
  try {
    const r = await requestJson("/api/login", { method: "POST", body: JSON.stringify({ username, password }) });
    showApp(r.username);
    await refreshAll();
    logsPaused = false;
    document.getElementById("toggleLogsBtn").textContent = "Pause";
    startLogStream();
  } catch (ex) { err.textContent = ex.message; }
});
document.getElementById("logoutBtn").addEventListener("click", async () => {
  await requestJson("/api/logout", { method: "POST" });
  showLogin();
});
document.getElementById("refreshBtn").addEventListener("click", refreshAll);
document.getElementById("applyFilterBtn").addEventListener("click", () => { currentPage = 1; loadKeys(1); });
document.getElementById("prevPageBtn").addEventListener("click", () => { if (currentPage > 1) loadKeys(currentPage - 1); });
document.getElementById("nextPageBtn").addEventListener("click", () => { if (currentPage < currentPages) loadKeys(currentPage + 1); });
document.getElementById("pageSizeSelect").addEventListener("change", () => { currentPage = 1; loadKeys(1); });
document.getElementById("toggleLogsBtn").addEventListener("click", () => {
  logsPaused = !logsPaused;
  document.getElementById("toggleLogsBtn").textContent = logsPaused ? "Resume" : "Pause";
  if (!logsPaused && !logEventSource) startLogStream();
});
document.getElementById("configSaveBtn").addEventListener("click", saveConfig);

bootstrap();