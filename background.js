let proxyConfig = { type: "socks", host: "127.0.0.1", port: 1080, username: "", password: "" };
let proxyRules = [];
let proxyLists = [];

let pE = {}, pS = {}, bE = {}, bS = {};
let pIp = {}, bIp = {}, pCidr = [], bCidr = [];
let pPac = [], bPac = [];
const ALL_WEB_URLS = ["http://*/*", "https://*/*", "ws://*/*", "wss://*/*"];
const tabHosts = {};
const tabProxied = {};

function normalizeRule(rule) {
  return String(rule || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
}

function isPacUrl(url) {
  try { return /\.(pac|dat)$/i.test(new URL(url).pathname); }
  catch (e) { return /\.pac(\?|#|$)/i.test(String(url || "")); }
}

function parseList(text) {
  const domains = new Set();
  const lines = String(text || "").split("\n");
  for (let line of lines) {
    line = line.trim().toLowerCase();
    if (!line || line.startsWith("!") || line.startsWith("#")) continue;
    const matchHosts = line.match(/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s]+)/);
    if (matchHosts) { domains.add(matchHosts[1]); continue; }
    if (line.startsWith("||")) {
      let endIdx = line.indexOf("^");
      if (endIdx === -1) endIdx = line.indexOf("/");
      if (endIdx === -1) endIdx = line.indexOf(":");
      if (endIdx === -1) endIdx = line.length;
      const domain = line.substring(2, endIdx).split("$")[0];
      if (domain) domains.add(domain);
      continue;
    }
    if (/^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i.test(line)) domains.add(line);
  }
  return Array.from(domains);
}

function ingestRemote(url, type, text) {
  if (PacParse.isHtmlDocument(text)) {
    throw new Error("Сервер отдал HTML-страницу (часто IPFS-шлюз), а не PAC. Не сохраняйте файл через «Сохранить как» — добавьте URL списка в расширение, оно скачает PAC само.");
  }
  if (PacParse.isPacText(text)) {
    const lists = PacParse.parsePacToLists(text);
    return {
      id: Date.now(),
      url,
      type,
      format: "pac",
      packed: lists.packed,
      patterns: lists.patterns,
      threePart: lists.threePart,
      extra: lists.extra,
      domains: lists.extra,
      ips: lists.ips,
      cidrs: lists.cidrs,
      domainCount: lists.domainCount,
      ipCount: lists.ipCount
    };
  }
  const domains = parseList(text);
  if (isPacUrl(url) && domains.length === 0) {
    const preview = String(text || "").replace(/\s+/g, " ").trim().slice(0, 180);
    throw new Error(preview ? `Ответ не похож на PAC-файл: ${preview}` : "Пустой ответ вместо PAC-файла");
  }
  return { id: Date.now(), url, type, format: "txt", domains, ips: [], cidrs: [], domainCount: domains.length, ipCount: 0 };
}

function addListTargets(list, exact, suffix, ipMap, cidrs) {
  (list.domains || []).forEach(d => {
    d = normalizeRule(d);
    if (!d) return;
    if (d.startsWith("*.")) suffix["." + d.slice(2)] = 1;
    else { exact[d] = 1; suffix["." + d] = 1; }
  });
  (list.ips || []).forEach(ip => {
    if (PacParse.IPV4_RE.test(ip)) ipMap[ip] = 1;
  });
  const compiled = PacParse.compileCidrs(list.cidrs);
  for (let i = 0; i < compiled.length; i++) cidrs.push(compiled[i]);
}

let hasIps = false;
let hasBlock = false;
let ffProxy = { type: "direct" };
const dnsCache = new Map();
const badgeWait = {};

function cacheProxy() {
  ffProxy = PacParse.userProxyToFirefox(proxyConfig);
  hasIps = false;
  for (const _ in pIp) { hasIps = true; break; }
  if (!hasIps) for (const _ in bIp) { hasIps = true; break; }
  if (!hasIps) hasIps = pCidr.length + bCidr.length > 0;
  hasBlock = bPac.length > 0 || bCidr.length > 0;
  if (!hasBlock) for (const _ in bE) { hasBlock = true; break; }
  if (!hasBlock) for (const _ in bS) { hasBlock = true; break; }
  if (!hasBlock) for (const _ in bIp) { hasBlock = true; break; }
}

function rebuildMaps() {
  pE = {}; pS = {}; bE = {}; bS = {};
  pIp = {}; bIp = {}; pCidr = []; bCidr = [];
  pPac = []; bPac = [];
  proxyRules.forEach(r => {
    r = normalizeRule(r);
    if (!r) return;
    if (r.startsWith("*.")) pS["." + r.slice(2)] = 1;
    else { pE[r] = 1; pS["." + r] = 1; }
  });
  proxyLists.forEach(list => {
    const block = list.type === "block";
    if (list.format === "pac" && list.packed) {
      (block ? bPac : pPac).push(PacParse.compilePacList(list));
      addListTargets({ ips: list.ips, cidrs: list.cidrs, domains: list.extra || [] },
        block ? bE : pE, block ? bS : pS, block ? bIp : pIp, block ? bCidr : pCidr);
      return;
    }
    addListTargets(list, block ? bE : pE, block ? bS : pS, block ? bIp : pIp, block ? bCidr : pCidr);
  });
  cacheProxy();
}

function matchMaps(host, exact, suffix) {
  host = (host || "").toLowerCase();
  if (!host) return false;
  if (exact[host]) return true;
  const parts = host.split(".");
  let current = "";
  for (let i = parts.length - 1; i >= 0; i--) {
    current = "." + parts[i] + current;
    if (suffix[current]) return true;
  }
  return false;
}

function isBlockedHost(host) {
  if (!hasBlock) return false;
  if (matchMaps(host, bE, bS) || PacParse.matchIpLiteral(host, bIp, bCidr)) return true;
  for (let i = 0; i < bPac.length; i++) {
    if (PacParse.matchPacHost(host, bPac[i])) return true;
  }
  return false;
}

function isProxiedHost(host) {
  if (matchMaps(host, pE, pS) || PacParse.matchIpLiteral(host, pIp, pCidr)) return true;
  for (let i = 0; i < pPac.length; i++) {
    if (PacParse.matchPacHost(host, pPac[i])) return true;
  }
  return false;
}

function decideProxySync(host) {
  if (isBlockedHost(host)) return { type: "http", host: "127.0.0.1", port: 9 };
  if (isProxiedHost(host)) return ffProxy;
  return null;
}

function resolveDns(host) {
  const now = Date.now();
  const hit = dnsCache.get(host);
  if (hit && now - hit.t < 60000) return Promise.resolve(hit.addrs);
  return browser.dns.resolve(host).then(rec => {
    const addrs = (rec && rec.addresses) || [];
    if (dnsCache.size >= 256) dnsCache.delete(dnsCache.keys().next().value);
    dnsCache.set(host, { t: now, addrs });
    return addrs;
  }).catch(() => {
    dnsCache.set(host, { t: now, addrs: [] });
    return [];
  });
}

function onProxyRequest(requestInfo) {
  let host = "";
  try { host = new URL(requestInfo.url).hostname.toLowerCase(); } catch (e) { return { type: "direct" }; }
  if (!host) return { type: "direct" };
  const tabId = requestInfo.tabId;
  const sync = decideProxySync(host);
  if (sync) {
    rememberTabHost(tabId, host, sync.port !== 9);
    scheduleBadge(tabId);
    return sync;
  }
  if (!hasIps || !browser.dns || !browser.dns.resolve || PacParse.IPV4_RE.test(host) || host.indexOf(":") >= 0) {
    rememberTabHost(tabId, host, false);
    return { type: "direct" };
  }
  return resolveDns(host).then(addrs => {
    for (let i = 0; i < addrs.length; i++) {
      const hit = decideProxySync(String(addrs[i] || "").replace(/^\[|\]$/g, ""));
      if (hit) {
        rememberTabHost(tabId, host, hit.port !== 9);
        scheduleBadge(tabId);
        return hit;
      }
    }
    rememberTabHost(tabId, host, false);
    return { type: "direct" };
  });
}

function applyProxy() {
  rebuildMaps();
}

function rememberTabHost(tabId, host, proxied) {
  if (tabId == null || tabId < 0 || !host) return;
  if (!tabHosts[tabId]) tabHosts[tabId] = new Set();
  tabHosts[tabId].add(host);
  if (proxied) {
    if (!tabProxied[tabId]) tabProxied[tabId] = new Set();
    tabProxied[tabId].add(host);
  }
}

function scheduleBadge(tabId) {
  if (tabId == null || tabId < 0 || badgeWait[tabId]) return;
  badgeWait[tabId] = setTimeout(() => {
    delete badgeWait[tabId];
    updateBadge(tabId);
  }, 50);
}

async function updateBadge(tabId) {
  if (tabId == null || tabId < 0) return;
  const n = tabProxied[tabId] ? tabProxied[tabId].size : 0;
  try {
    await browser.action.setBadgeBackgroundColor({ tabId, color: "#5865f2" });
    if (browser.action.setBadgeTextColor) await browser.action.setBadgeTextColor({ tabId, color: "#ffffff" });
    await browser.action.setBadgeText({ tabId, text: n ? String(n) : "" });
  } catch (e) {}
}

async function refreshActiveBadge() {
  try {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    if (tabs[0]) await updateBadge(tabs[0].id);
  } catch (e) {}
}

browser.proxy.onRequest.addListener(onProxyRequest, { urls: ALL_WEB_URLS });

browser.webRequest.onAuthRequired.addListener(
  function (details) {
    if (details.isProxy && proxyConfig.username && proxyConfig.password) {
      return { authCredentials: { username: proxyConfig.username, password: proxyConfig.password } };
    }
    return {};
  },
  { urls: ALL_WEB_URLS },
  ["blocking"]
);

browser.tabs.onRemoved.addListener((tabId) => {
  delete tabHosts[tabId];
  delete tabProxied[tabId];
});

browser.tabs.onActivated.addListener((info) => updateBadge(info.tabId));
browser.tabs.onUpdated.addListener((tabId, change) => {
  if (change.status === "loading" && change.url) {
    tabHosts[tabId] = new Set();
    tabProxied[tabId] = new Set();
  }
  updateBadge(tabId);
});

async function fetchAndStoreList(url, type, existingId) {
  const r = await fetch(url, {
    cache: "no-store",
    headers: { Accept: "application/x-ns-proxy-autoconfig, text/plain, application/javascript, */*" },
    signal: AbortSignal.timeout ? AbortSignal.timeout(45000) : undefined
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${text.replace(/\s+/g, " ").trim().slice(0, 160)}`);
  const item = ingestRemote(url, type, text);
  if (existingId != null) {
    item.id = existingId;
    const idx = proxyLists.findIndex(x => x.id === existingId);
    if (idx >= 0) proxyLists[idx] = Object.assign({}, proxyLists[idx], item, { url, type: proxyLists[idx].type || type });
    else proxyLists.push(item);
  } else {
    proxyLists.push(item);
  }
  delete item.pacScript;
  delete item.pacIndex;
  await browser.storage.local.set({ proxyLists });
  return item;
}

async function updateAllLists() {
  if (!proxyLists.length) return { updated: 0 };
  let updated = 0;
  for (const list of proxyLists) {
    if (!list.url) continue;
    try {
      await fetchAndStoreList(list.url, list.type, list.id);
      updated++;
    } catch (e) {}
  }
  rebuildMaps();
  await refreshActiveBadge();
  return { updated };
}

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "fetchList") {
    fetchAndStoreList(msg.url, msg.type)
      .then(() => applyProxy())
      .then(() => sendResponse({ success: true }))
      .catch(e => sendResponse({ success: false, error: String(e.message || e) }));
    return true;
  }
  if (msg.action === "refreshLists") {
    updateAllLists()
      .then(res => sendResponse({ success: true, updated: res.updated }))
      .catch(e => sendResponse({ success: false, error: String(e.message || e) }));
    return true;
  }
  if (msg.action === "getUnproxiedDomains") {
    const domains = tabHosts[msg.tabId] ? Array.from(tabHosts[msg.tabId]) : [];
    sendResponse({ domains: domains.filter(d => !isProxiedHost(d) && !isBlockedHost(d)) });
    return true;
  }
});

browser.alarms.create("updateLists", { periodInMinutes: 60 });
browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "updateLists") updateAllLists();
});

browser.storage.onChanged.addListener(async (changes) => {
  let need = false;
  if (changes.proxyConfig) { proxyConfig = changes.proxyConfig.newValue || proxyConfig; need = true; }
  if (changes.proxyRules) { proxyRules = changes.proxyRules.newValue || []; need = true; }
  if (changes.proxyLists) { proxyLists = changes.proxyLists.newValue || []; need = true; }
  if (need) {
    rebuildMaps();
    await refreshActiveBadge();
  }
});

function isStalePac(list) {
  if (!list || list.format !== "pac" || !list.url) return false;
  if (list.pacScript || list.pacIndex) return true;
  if (list.packed && (list.domainCount || 0) >= 100) return false;
  const n = (list.domains && list.domains.length) || 0;
  const ips = (list.ips && list.ips.length) || 0;
  if (!n && !ips) return true;
  if (n > 0 && n < 100 && !ips) return true;
  return false;
}

function stripLegacyPac(list) {
  if (!list) return list;
  delete list.pacScript;
  delete list.pacIndex;
  return list;
}

browser.storage.local.get(["proxyConfig", "proxyRules", "proxyLists"]).then(async (res) => {
  if (res.proxyConfig) proxyConfig = res.proxyConfig;
  if (res.proxyRules) proxyRules = res.proxyRules;
  if (res.proxyLists) proxyLists = res.proxyLists.map(stripLegacyPac);
  const stale = proxyLists.some(isStalePac);
  try { await browser.proxy.settings.clear({}); } catch (e) {}
  rebuildMaps();
  await refreshActiveBadge();
  if (stale) updateAllLists();
});
