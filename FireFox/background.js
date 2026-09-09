let proxyConfig = { type: "socks", host: "", port: 0, username: "", password: "" };
let proxyRules = [];
let directRules = [];
let proxyLists = [];
let extensionEnabled = false;

function configFromServers(list) {
  const on = (list || []).find(p => p.enabled && p.host && Number(p.port) > 0);
  if (!on) return { type: "socks", host: "", port: 0, username: "", password: "" };
  return {
    type: on.type || "socks",
    host: String(on.host).trim(),
    port: Number(on.port),
    username: on.username || "",
    password: on.password || ""
  };
}

function withActiveProxy(list, activeId) {
  const out = (list || []).map(p => Object.assign({}, p, { enabled: false }));
  if (!out.length) return out;
  const has = activeId != null && out.some(p => p.id === activeId);
  const id = has ? activeId : out[0].id;
  out.forEach(p => { p.enabled = p.id === id; });
  return out;
}

function migrateProxyServers(servers, fallback) {
  let list = Array.isArray(servers) ? servers.map(p => Object.assign({}, p)) : [];
  if (!list.length && fallback && fallback.host) {
    list = [{
      id: Date.now(),
      type: fallback.type || "socks",
      host: fallback.host,
      port: Number(fallback.port) || 1080,
      username: fallback.username || "",
      password: fallback.password || "",
      enabled: true
    }];
  }
  const keep = (list.find(p => p.enabled) || list[0] || {}).id;
  return withActiveProxy(list, keep);
}

let pE = {}, pS = {}, bE = {}, bS = {}, dE = {}, dS = {};
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

function addHostRules(rules, exact, suffix) {
  (rules || []).forEach(r => {
    r = normalizeRule(r);
    if (!r) return;
    if (r.startsWith("*.")) suffix["." + r.slice(2)] = 1;
    else { exact[r] = 1; suffix["." + r] = 1; }
  });
}

function rebuildMaps() {
  pE = {}; pS = {}; bE = {}; bS = {}; dE = {}; dS = {};
  pIp = {}; bIp = {}; pCidr = []; bCidr = [];
  pPac = []; bPac = [];
  addHostRules(proxyRules, pE, pS);
  addHostRules(directRules, dE, dS);
  proxyLists.forEach(list => {
    if (list.format === "pac" && list.packed) {
      pPac.push(PacParse.compilePacList(list));
      addListTargets({ ips: list.ips, cidrs: list.cidrs, domains: list.extra || [] }, pE, pS, pIp, pCidr);
      return;
    }
    addListTargets(list, pE, pS, pIp, pCidr);
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

function isDirectHost(host) {
  return matchMaps(host, dE, dS);
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

function listLabel(list) {
  const name = String((list && list.name) || "").trim();
  if (name) return name;
  try { return new URL(list.url).hostname; } catch (e) {}
  return String((list && list.url) || "список");
}

function findCoveringList(host) {
  host = String(host || "").toLowerCase();
  if (host.indexOf("www.") === 0) host = host.slice(4);
  if (!host) return null;
  let pacIdx = 0;
  for (let i = 0; i < proxyLists.length; i++) {
    const list = proxyLists[i];
    const e = {}, s = {}, ip = {};
    const cidr = [];
    if (list.format === "pac" && list.packed) {
      const compiled = pPac[pacIdx++];
      if (compiled && PacParse.matchPacHost(host, compiled)) return list;
      addListTargets({ ips: list.ips, cidrs: list.cidrs, domains: list.extra || [] }, e, s, ip, cidr);
    } else {
      addListTargets(list, e, s, ip, cidr);
    }
    if (matchMaps(host, e, s) || PacParse.matchIpLiteral(host, ip, cidr)) return list;
  }
  return null;
}

function listedViaParent(host) {
  const parts = String(host || "").split(".").filter(Boolean);
  for (let i = 1; i <= parts.length - 2; i++) {
    if (findCoveringList(parts.slice(i).join("."))) return true;
  }
  return false;
}

const fetchProxyHosts = {};
const fetchDirectHosts = {};

function canonListUrl(url) {
  return String(url || "").trim().replace(/\/+$/, "").toLowerCase();
}

function listMeta(msg, existing) {
  const name = msg && msg.name != null ? String(msg.name).trim() : ((existing && existing.name) || "");
  let hours = Number(msg && msg.intervalHours);
  if (!(hours > 0)) hours = existing && Number(existing.intervalHours) > 0 ? Number(existing.intervalHours) : 12;
  if (hours > 168) hours = 168;
  const viaProxy = msg && msg.viaProxy != null ? !!msg.viaProxy : !!(existing && existing.viaProxy);
  return { name, intervalHours: hours, viaProxy };
}

function findListByUrl(url, exceptId) {
  const c = canonListUrl(url);
  return proxyLists.find(l => canonListUrl(l.url) === c && (exceptId == null || l.id !== exceptId));
}

function decideProxySync(host) {
  if (fetchDirectHosts[host]) return { type: "direct" };
  if (fetchProxyHosts[host]) return ffProxy;
  if (!extensionEnabled) return { type: "direct" };
  if (isDirectHost(host)) return { type: "direct" };
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
    rememberTabHost(tabId, host, sync.type !== "direct" && sync.port !== 9);
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
  const n = extensionEnabled && tabProxied[tabId] ? tabProxied[tabId].size : 0;
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

async function withFetchRoute(url, viaProxy, fn) {
  let host = "";
  try { host = new URL(url).hostname.toLowerCase(); } catch (e) {}
  const bucket = viaProxy ? fetchProxyHosts : fetchDirectHosts;
  if (host) bucket[host] = (bucket[host] || 0) + 1;
  try { return await fn(); }
  finally {
    if (host) {
      bucket[host]--;
      if (bucket[host] <= 0) delete bucket[host];
    }
  }
}

async function fetchAndStoreList(url, type, existingId, msg) {
  url = String(url || "").trim();
  if (!url.startsWith("http")) throw new Error("Введите корректный URL");
  if (findListByUrl(url, existingId)) throw new Error("Список добавить нельзя, он уже существует");
  const existing = existingId != null ? proxyLists.find(x => x.id === existingId) : null;
  const meta = listMeta(msg || {}, existing);
  const item = await withFetchRoute(url, meta.viaProxy, async () => {
    const r = await fetch(url, {
      cache: "no-store",
      headers: { Accept: "application/x-ns-proxy-autoconfig, text/plain, application/javascript, */*" },
      signal: AbortSignal.timeout ? AbortSignal.timeout(45000) : undefined
    });
    const text = await r.text();
    if (!r.ok) throw new Error(`HTTP ${r.status}: ${text.replace(/\s+/g, " ").trim().slice(0, 160)}`);
    return ingestRemote(url, "proxy", text);
  });
  delete item.pacScript;
  delete item.pacIndex;
  item.name = meta.name;
  item.intervalHours = meta.intervalHours;
  item.viaProxy = meta.viaProxy;
  item.updatedAt = Date.now();
  if (existingId != null) {
    item.id = existingId;
    const idx = proxyLists.findIndex(x => x.id === existingId);
    if (idx >= 0) proxyLists[idx] = Object.assign({}, proxyLists[idx], item, { url, type: "proxy" });
    else proxyLists.push(item);
  } else {
    proxyLists.push(item);
  }
  await browser.storage.local.set({ proxyLists });
  return item;
}

async function saveListMeta(msg) {
  const idx = proxyLists.findIndex(x => x.id === msg.id);
  if (idx < 0) throw new Error("Список не найден");
  const url = String(msg.url || proxyLists[idx].url || "").trim();
  if (!url.startsWith("http")) throw new Error("Введите корректный URL");
  if (findListByUrl(url, msg.id)) throw new Error("Список добавить нельзя, он уже существует");
  const meta = listMeta(msg, proxyLists[idx]);
  proxyLists[idx].name = meta.name;
  proxyLists[idx].intervalHours = meta.intervalHours;
  proxyLists[idx].viaProxy = meta.viaProxy;
  proxyLists[idx].type = "proxy";
  proxyLists[idx].url = url;
  await browser.storage.local.set({ proxyLists });
}

async function updateAllLists() {
  if (!proxyLists.length) return { updated: 0 };
  let updated = 0;
  for (const list of proxyLists) {
    if (!list.url) continue;
    try {
      await fetchAndStoreList(list.url, list.type, list.id, list);
      updated++;
    } catch (e) {}
  }
  rebuildMaps();
  await refreshActiveBadge();
  return { updated };
}

async function updateDueLists() {
  if (!proxyLists.length) return { updated: 0 };
  const now = Date.now();
  let updated = 0;
  for (const list of proxyLists) {
    if (!list.url) continue;
    const hours = Number(list.intervalHours) > 0 ? Number(list.intervalHours) : 12;
    if (now - (Number(list.updatedAt) || 0) < hours * 3600000) continue;
    try {
      await fetchAndStoreList(list.url, list.type, list.id, list);
      updated++;
    } catch (e) {}
  }
  if (updated) {
    rebuildMaps();
    await refreshActiveBadge();
  }
  return { updated };
}

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "fetchList") {
    fetchAndStoreList(msg.url, msg.type, msg.id, msg)
      .then(() => applyProxy())
      .then(() => sendResponse({ success: true }))
      .catch(e => sendResponse({ success: false, error: String(e.message || e) }));
    return true;
  }
  if (msg.action === "saveListMeta") {
    saveListMeta(msg)
      .then(() => applyProxy())
      .then(() => sendResponse({ success: true }))
      .catch(e => sendResponse({ success: false, error: String(e.message || e) }));
    return true;
  }
  if (msg.action === "refreshList") {
    const list = proxyLists.find(x => x.id === msg.id);
    if (!list) {
      sendResponse({ success: false, error: "Список не найден" });
      return true;
    }
    fetchAndStoreList(list.url, list.type, list.id, list)
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
  if (msg.action === "coverInfoMany") {
    const hosts = Array.isArray(msg.hosts) ? msg.hosts : [];
    const covers = {};
    hosts.forEach(h => {
      const host = normalizeRule(h).replace(/^\*\./, "");
      if (!host || covers[host]) return;
      const list = findCoveringList(host);
      covers[host] = { listed: !!list, listedParent: !!list && listedViaParent(host) };
    });
    sendResponse({ covers });
    return true;
  }
  if (msg.action === "coverInfo") {
    const host = normalizeRule(msg.host || "").replace(/^\*\./, "");
    const list = findCoveringList(host);
    sendResponse({
      listed: !!list,
      listedParent: !!list && listedViaParent(host),
      listName: list ? listLabel(list) : ""
    });
    return true;
  }
  if (msg.action === "getTabDomains" || msg.action === "getUnproxiedDomains") {
    const domains = tabHosts[msg.tabId] ? Array.from(tabHosts[msg.tabId]) : [];
    sendResponse({
      domains: msg.action === "getTabDomains"
        ? domains.sort()
        : domains.filter(d => !isProxiedHost(d) && !isBlockedHost(d))
    });
    return true;
  }
});

browser.alarms.create("updateLists", { periodInMinutes: 30 });
browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "updateLists") updateDueLists();
});

browser.storage.onChanged.addListener(async (changes) => {
  let need = false;
  if (changes.proxyServers) {
    proxyConfig = configFromServers(migrateProxyServers(changes.proxyServers.newValue || [], null));
    need = true;
  } else if (changes.proxyConfig) {
    proxyConfig = changes.proxyConfig.newValue || proxyConfig;
    need = true;
  }
  if (changes.proxyRules) { proxyRules = changes.proxyRules.newValue || []; need = true; }
  if (changes.directRules) { directRules = changes.directRules.newValue || []; need = true; }
  if (changes.proxyLists) { proxyLists = changes.proxyLists.newValue || []; need = true; }
  if (changes.extensionEnabled) {
    extensionEnabled = !!changes.extensionEnabled.newValue && !!(proxyConfig && proxyConfig.host);
    need = true;
  }
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

browser.storage.local.get(["proxyConfig", "proxyServers", "proxyRules", "directRules", "proxyLists", "extensionEnabled"]).then(async (res) => {
  const servers = migrateProxyServers(res.proxyServers, res.proxyConfig);
  proxyConfig = configFromServers(servers);
  if (res.extensionEnabled == null) extensionEnabled = !!(proxyConfig && proxyConfig.host);
  else extensionEnabled = !!res.extensionEnabled && !!(proxyConfig && proxyConfig.host);
  const persist = {};
  if (JSON.stringify(servers) !== JSON.stringify(res.proxyServers || [])) {
    persist.proxyServers = servers;
    persist.proxyConfig = proxyConfig;
  }
  if (res.extensionEnabled !== extensionEnabled) persist.extensionEnabled = extensionEnabled;
  if (res.proxyRules) proxyRules = res.proxyRules;
  if (res.directRules) directRules = res.directRules;
  if (res.proxyLists) proxyLists = res.proxyLists.map(stripLegacyPac);
  if (proxyLists.some(l => l.type === "block")) {
    proxyLists = proxyLists.map(l => Object.assign({}, l, { type: "proxy" }));
    persist.proxyLists = proxyLists;
  }
  if (Object.keys(persist).length) await browser.storage.local.set(persist);
  const stale = proxyLists.some(isStalePac);
  try { await browser.proxy.settings.clear({}); } catch (e) {}
  rebuildMaps();
  await refreshActiveBadge();
  if (stale) updateAllLists();
});
