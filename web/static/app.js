let currentPage = 1;
let currentPages = 1;
let currentPageSize = 20;
let logEventSource = null;
let logsPaused = false;

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
    if (el.dataset.view === "logs") loadRecentLogs();
  });
});

async function requestJson(url, options = {}) {
  const r = await fetch(url, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (r.status === 401) {
    showLogin();
    throw new Error("Unauthorized");
  }
  const data = await r.json();
  if (!r.ok) throw new Error(data.detail || "HTTP " + r.status);
  return data;
}

function showLogin() {
  document.getElementById("loginView").classList.remove("hidden");
  document.getElementById("appView").classList.add("hidden");
  if (logEventSource) {
    logEventSource.close();
    logEventSource = null;
  }
}

function showApp(username) {
  document.getElementById("loginView").classList.add("hidden");
  document.getElementById("appView").classList.remove("hidden");
  document.getElementById("currentUser").textContent = username;
}

function badge(status, extra) {
  return '<span class="badge ' + status + ' ' + (extra || '') + '">' + status + '</span>';
}

function esc(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function formatPercent(value) {
  return (Number(value || 0) * 100).toFixed(1) + "%";
}

function renderChartRows(rows, emptyText) {
  if (!rows.length) return '<div class="chart-row muted">' + esc(emptyText) + '</div>';
  return rows.join("");
}

async function loadStats() {
  const s = await requestJson("/api/stats");
  const overview = s.overview || {};
  const run = s.run_status || {};
  const quota = s.quota || {};
  const sourceBreakdown = s.source_breakdown || [];
  const platformBreakdown = s.platform_breakdown || {};
  const statusBreakdown = s.status_breakdown || {};
  const queryQuality = s.query_quality || [];
  const progressFeed = s.progress_feed || [];

  document.getElementById("statValid").textContent = overview.valid_total ?? "--";
  document.getElementById("statTotal").textContent = overview.discovered_total ?? "--";
  document.getElementById("statScanned").textContent = overview.scanned_files ?? "--";
  document.getElementById("statHighValue").textContent = overview.high_value_total ?? "--";
  document.getElementById("statStatus").textContent = run.status_text || "--";
  document.getElementById("statQueue").textContent = run.queue_size ?? "--";

  const statusRows = [
    '<div class="chart-row"><span>Current source</span><span class="num">' + esc(run.current_source || "idle") + '</span></div>',
    '<div class="chart-row"><span>Current target</span><span class="num">' + esc(run.current_target || run.current_keyword || "--") + '</span></div>',
    '<div class="chart-row"><span>Current round</span><span class="num">' + esc((run.round_keyword_index || 0) + "/" + (run.round_total_keywords || 0)) + '</span></div>',
    '<div class="chart-row"><span>Budget used</span><span class="num">' + esc((run.search_budget_used || 0) + "/" + (run.search_budget_total || 0)) + '</span></div>',
    '<div class="chart-row"><span>Token slot</span><span class="num">' + esc(run.tokens_text || "--") + '</span></div>',
    '<div class="chart-row"><span>Quota hits</span><span class="num">' + esc(String(overview.quota_exceeded_total ?? 0)) + '</span></div>'
  ];
  document.getElementById("statusChart").innerHTML = renderChartRows(statusRows, "No run data");

  const sourceRows = sourceBreakdown.slice(0, 8).map(item =>
    '<div class="chart-row"><span>' + esc(item.source) + '</span><span class="num">valid ' + item.keys_valid + ' | hit ' + formatPercent(item.hit_rate) + '</span></div>'
  );
  document.getElementById("platformChart").innerHTML = renderChartRows(sourceRows, "No source data");

  const progressRows = progressFeed.slice(-10).map(item =>
    '<div class="bar-row"><span class="muted">' + esc(item.channel || "系统") + '</span><div class="bar-track"><div class="bar-fill" style="width:100%"></div></div><span>' + esc(item.message || "") + '</span></div>'
  );
  document.getElementById("dailyChart").innerHTML = progressRows.join("") || '<div class="muted">No progress yet</div>';

  const quotaHtml = (quota.items || []).map(item => {
    if (!item.ok) {
      return '<div class="quota-card"><div class="chart-row"><strong>Token ' + item.token_index + '</strong><span class="muted">' + esc(item.error || "N/A") + '</span></div></div>';
    }
    return '<div class="quota-card">'
      + '<div class="chart-row"><strong>' + esc(item.login || ("Token " + item.token_index)) + '</strong><span>' + (item.code_search_remaining ?? "--") + '/' + (item.code_search_limit ?? "--") + '</span></div>'
      + '<div class="chart-row"><span class="muted">Reset</span><span class="muted">' + esc(item.code_search_reset_bj || "--") + '</span></div>'
      + '<div class="chart-row"><span class="muted">Health</span><span class="muted">' + Number(item.health_score ?? 100).toFixed(1) + '</span></div>'
      + '<div class="chart-row"><span class="muted">Counts</span><span class="muted">OK ' + (item.success_count || 0) + ' / Err ' + (item.failure_count || 0) + '</span></div>'
      + '</div>';
  }).join("");
  document.getElementById("quotaStatus").innerHTML = quotaHtml || '<div class="chart-row muted">No token data</div>';

  const pp = s.proxy_pool || {};
  if (!pp.enabled) {
    document.getElementById("proxyPoolStatus").innerHTML = '<div class="chart-row muted">Proxy pool disabled</div>';
  } else {
    const top = (pp.proxies || []).slice(0, 8);
    document.getElementById("proxyPoolStatus").innerHTML = '<div class="chart-row"><strong>Healthy ' + (pp.healthy || 0) + '/' + (pp.total || 0) + '</strong><span class="muted">Unhealthy ' + (pp.unhealthy || 0) + '</span></div>'
      + top.map(p => '<div class="chart-row"><span>' + esc(p.url || "") + '</span><span class="muted">score ' + Number(p.health_score || 0).toFixed(1) + '</span></div>').join("");
  }

  const qualityRows = [];
  queryQuality.slice(0, 6).forEach(item => {
    qualityRows.push('<div class="chart-row"><span>' + esc(item.keyword) + '</span><span class="num">score ' + Number(item.score || 0).toFixed(2) + ' | valid ' + formatPercent(item.valid_rate) + '</span></div>');
  });
  Object.entries(platformBreakdown).slice(0, 4).forEach(([platform, count]) => {
    qualityRows.push('<div class="chart-row"><span>' + esc(platform) + '</span><span class="num">' + count + '</span></div>');
  });
  Object.entries(statusBreakdown).forEach(([status, count]) => {
    qualityRows.push('<div class="chart-row"><span>' + esc(status) + '</span><span class="num">' + count + '</span></div>');
  });
  document.getElementById("queryQuality").innerHTML = renderChartRows(qualityRows.slice(0, 12), "No quality data");
}

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

async function loadConfig() {
  try {
    const cfg = await requestJson("/api/config");
    const effective = cfg.effective || {};
    const envCfg = cfg.env || {};
    const persisted = cfg.persisted || {};

    document.getElementById("cfgProxyUrl").value = effective.proxy_url || persisted.proxy_url || "";
    document.getElementById("cfgDynamicProxySourceUrl").value = effective.dynamic_proxy_source_url || persisted.dynamic_proxy_source_url || "";
    document.getElementById("cfgEnvProxyUrl").value = envCfg.proxy_url || "(not set)";
    document.getElementById("cfgEnvDynamicProxySourceUrl").value = envCfg.dynamic_proxy_source_url || "(not set)";
    document.getElementById("cfgProviders").value = (effective.enabled_providers || []).join(", ");
    document.getElementById("cfgKeywords").value = (effective.search_keywords || []).join(",\n");
    document.getElementById("cfgThreads").value = effective.consumer_threads || 20;
    document.getElementById("cfgTimeout").value = effective.request_timeout || 15;
    document.getElementById("cfgContextWindow").value = effective.context_window || 10;
    document.getElementById("cfgConcurrency").value = effective.max_concurrency || 100;
    document.getElementById("cfgRedisUrl").value = effective.redis_url || persisted.redis_url || "";
    document.getElementById("cfgCircuitBreaker").checked = effective.circuit_breaker_enabled !== false;

    const tokenHtml = (envCfg.github_tokens_masked || []).map(t => '<span class="token-badge">' + esc(t) + '</span>').join("")
      || '<span class="muted">No tokens configured (set GITHUB_TOKENS env)</span>';
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
    const dynamicProxySourceUrl = document.getElementById("cfgDynamicProxySourceUrl").value.trim();
    const providers = document.getElementById("cfgProviders").value.split(",").map(s => s.trim()).filter(Boolean);
    const kwText = document.getElementById("cfgKeywords").value;
    const keywords = kwText.split(/[,\n]+/).map(s => s.trim()).filter(Boolean);
    const payload = {
      proxy_url: proxy,
      dynamic_proxy_source_url: dynamicProxySourceUrl,
      enabled_providers: providers,
      search_keywords: keywords,
      consumer_threads: parseInt(document.getElementById("cfgThreads").value, 10) || 20,
      request_timeout: parseInt(document.getElementById("cfgTimeout").value, 10) || 15,
      context_window: parseInt(document.getElementById("cfgContextWindow").value, 10) || 10,
      max_concurrency: parseInt(document.getElementById("cfgConcurrency").value, 10) || 100,
      redis_url: document.getElementById("cfgRedisUrl").value.trim(),
      circuit_breaker_enabled: document.getElementById("cfgCircuitBreaker").checked,
    };
    const res = await requestJson("/api/config/update", { method: "POST", body: JSON.stringify(payload) });
    if (res.ok) {
      result.className = "config-result ok";
      result.textContent = res.message || "Configuration saved successfully";
      await loadConfig();
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

async function loadRecentLogs() {
  const data = await requestJson("/api/logs?lines=120");
  const feed = data.progress_feed || [];
  const out = document.getElementById("logOutput");
  out.textContent = feed.map(entry => `[${entry.timestamp || ""}] [${entry.channel || "系统"}] ${entry.message || ""}`.trim()).join("\n");
  out.scrollTop = out.scrollHeight;
  document.getElementById("logCount").textContent = feed.length + " entries";
}

function appendLogEntry(entry) {
  const line = entry && entry.message
    ? `[${entry.timestamp || ""}] [${entry.channel || "系统"}] ${entry.message}`.trim()
    : (entry?.line || "");
  const out = document.getElementById("logOutput");
  out.textContent += (out.textContent ? "\n" : "") + line;
  out.scrollTop = out.scrollHeight;
  const lines = out.textContent.split("\n");
  if (lines.length > 800) out.textContent = lines.slice(-800).join("\n");
  document.getElementById("logCount").textContent = lines.length + " entries";
}

function startLogStream() {
  if (logEventSource) logEventSource.close();
  logEventSource = new EventSource("/api/logs/stream", { withCredentials: true });
  logEventSource.onmessage = e => {
    if (logsPaused) return;
    const payload = JSON.parse(e.data);
    appendLogEntry(payload.entry || { line: payload.line || "" });
  };
  logEventSource.onerror = () => {
    logEventSource.close();
    logEventSource = null;
    setTimeout(() => {
      if (!logsPaused) startLogStream();
    }, 5000);
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
    await loadRecentLogs();
    startLogStream();
  } catch {
    showLogin();
  }
}

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
    await loadRecentLogs();
    logsPaused = false;
    document.getElementById("toggleLogsBtn").textContent = "Pause";
    startLogStream();
  } catch (ex) {
    err.textContent = ex.message;
  }
});

document.getElementById("logoutBtn").addEventListener("click", async () => {
  await requestJson("/api/logout", { method: "POST" });
  showLogin();
});

document.getElementById("refreshBtn").addEventListener("click", refreshAll);
document.getElementById("applyFilterBtn").addEventListener("click", () => {
  currentPage = 1;
  loadKeys(1);
});
document.getElementById("prevPageBtn").addEventListener("click", () => {
  if (currentPage > 1) loadKeys(currentPage - 1);
});
document.getElementById("nextPageBtn").addEventListener("click", () => {
  if (currentPage < currentPages) loadKeys(currentPage + 1);
});
document.getElementById("pageSizeSelect").addEventListener("change", () => {
  currentPage = 1;
  loadKeys(1);
});
document.getElementById("toggleLogsBtn").addEventListener("click", () => {
  logsPaused = !logsPaused;
  document.getElementById("toggleLogsBtn").textContent = logsPaused ? "Resume" : "Pause";
  if (!logsPaused && !logEventSource) startLogStream();
});
document.getElementById("configSaveBtn").addEventListener("click", saveConfig);

bootstrap();


document.getElementById("fetchProxyBtn")?.addEventListener("click", async () => {
  const result = document.getElementById("fetchProxyResult");
  result.textContent = "Fetching...";
  try {
    const res = await requestJson("/api/proxy-source/fetch", { method: "POST", body: JSON.stringify({}) });
    if (res.ok) {
      result.textContent = res.message || ("Fetched proxy: " + (res.proxy_url || ""));
      await loadStats();
    } else {
      result.textContent = res.message || "Fetch failed";
    }
  } catch (e) {
    result.textContent = "Error: " + e.message;
  }
});
