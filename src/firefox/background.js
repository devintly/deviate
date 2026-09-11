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

let pE = {}, pS = {}, dE = {}, dS = {};
let pIp = {}, dIp = {}, pCidr = [];
let pPac = [];
let compiledLists = [];
const ALL_WEB_URLS = ["http://*/*", "https://*/*", "ws://*/*", "wss://*/*"];
const tabHosts = {};
const tabProxied = {};

function isAcceptableHost(h) {
  h = String(h || "");
  if (!h || /\s/.test(h) || /[^\x00-\x7F]/.test(h)) return false;
  if (PacParse.IPV4_RE.test(h) || h.indexOf(":") >= 0) return true;
  if (!/^[a-z0-9.:\[\]-]+$/i.test(h)) return false;
  return h.indexOf(".") >= 0 && h.indexOf("..") < 0;
}

function normalizeRule(rule) {
  const trimmed = String(rule || "").trim();
  if (!trimmed || /\s/.test(trimmed)) return "";
  let s = trimmed.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (/\s/.test(s)) return "";
  const wild = s.startsWith("*.");
  if (wild) s = s.slice(2);
  s = s.replace(/^\.+|\.+$/g, "");
  if (!s || !isAcceptableHost(s)) return "";
  if (PacParse.IPV4_RE.test(s) || s.indexOf(":") >= 0) return s;
  return wild ? "*." + s : s;
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
let ffProxy = { type: "direct" };
const dnsCache = new Map();
const badgeWait = {};
const badgeText = {};
let badgeColorsReady = false;

function cacheProxy() {
  ffProxy = PacParse.userProxyToFirefox(proxyConfig);
  hasIps = false;
  for (const _ in pIp) { hasIps = true; break; }
  if (!hasIps) for (const _ in dIp) { hasIps = true; break; }
  if (!hasIps) hasIps = pCidr.length > 0;
}

function addHostRules(rules, exact, suffix, ipMap) {
  (rules || []).forEach(r => {
    r = normalizeRule(r);
    if (!r) return;
    const wild = r.startsWith("*.");
    const host = wild ? r.slice(2) : r;
    if (!host) return;
    if (PacParse.IPV4_RE.test(host) || host.indexOf(":") >= 0) {
      exact[host] = 1;
      if (ipMap && PacParse.IPV4_RE.test(host)) ipMap[host] = 1;
      return;
    }
    if (wild) suffix["." + host] = 1;
    else exact[host] = 1;
  });
}

function rebuildMaps() {
  const nextPE = {}, nextPS = {}, nextDE = {}, nextDS = {};
  const nextPIp = {}, nextDIp = {}, nextPCidr = [];
  const nextPPac = [];
  const nextCompiledLists = [];

  addHostRules(proxyRules, nextPE, nextPS, nextPIp);
  addHostRules(directRules, nextDE, nextDS, nextDIp);

  proxyLists.forEach(list => {
    const lExact = {}, lSuffix = {}, lIp = {}, lCidr = [];
    let lPac = null;
    if (list.format === "pac" && list.packed) {
      lPac = PacParse.compilePacList(list);
      nextPPac.push(lPac);
      addListTargets({ ips: list.ips, cidrs: list.cidrs, domains: list.extra || [] }, nextPE, nextPS, nextPIp, nextPCidr);
      addListTargets({ ips: list.ips, cidrs: list.cidrs, domains: list.extra || [] }, lExact, lSuffix, lIp, lCidr);
    } else {
      addListTargets(list, nextPE, nextPS, nextPIp, nextPCidr);
      addListTargets(list, lExact, lSuffix, lIp, lCidr);
    }
    nextCompiledLists.push({ list, pac: lPac, exact: lExact, suffix: lSuffix, ip: lIp, cidr: lCidr });
  });

  pE = nextPE; pS = nextPS; dE = nextDE; dS = nextDS;
  pIp = nextPIp; dIp = nextDIp; pCidr = nextPCidr; pPac = nextPPac;
  compiledLists = nextCompiledLists;
  cacheProxy();
  recountTabProxied();
}

function matchMaps(host, exact, suffix) {
  if (!host) return false;
  host = host.toLowerCase();
  if (exact[host]) return true;
  if (host.startsWith("www.") && exact[host.slice(4)]) return true;
  const parts = host.split(".");
  let current = "";
  for (let i = parts.length - 1; i >= 0; i--) {
    current = "." + parts[i] + current;
    if (suffix[current]) return true;
  }
  return false;
}

function isDirectHost(host) {
  return matchMaps(host, dE, dS) || PacParse.matchIpLiteral(host, dIp, []);
}

function isProxiedHost(host) {
  if (matchMaps(host, pE, pS) || PacParse.matchIpLiteral(host, pIp, pCidr)) return true;
  for (let i = 0; i < pPac.length; i++) {
    if (PacParse.matchPacHost(host, pPac[i])) return true;
  }
  return false;
}

function hostIsProxied(host) {
  if (!extensionEnabled || !host) return false;
  if (isDirectHost(host)) return false;
  return isProxiedHost(host);
}

function listLabel(list) {
  const name = String((list && list.name) || "").trim();
  if (name) return name;
  try { return new URL(list.url).hostname; } catch (e) {}
  return String((list && list.url) || "список");
}

function findCoveringList(host) {
  if (!host) return null;
  host = String(host).toLowerCase();
  for (let i = 0; i < compiledLists.length; i++) {
    const entry = compiledLists[i];
    if (entry.pac && PacParse.matchPacHost(host, entry.pac)) return entry.list;
    if (matchMaps(host, entry.exact, entry.suffix) || PacParse.matchIpLiteral(host, entry.ip, entry.cidr)) return entry.list;
  }
  return null;
}

function listedParentHost(host) {
  const parts = String(host || "").toLowerCase().split(".").filter(Boolean);
  for (let i = 1; i <= parts.length - 2; i++) {
    const parent = parts.slice(i).join(".");
    if (findCoveringList(parent)) return parent;
  }
  return "";
}

function listedParentRule(host) {
  const parent = listedParentHost(host);
  if (!parent) return "";
  if (PacParse.IPV4_RE.test(parent) || parent.indexOf(":") >= 0) return parent;
  return "*." + parent;
}

function coverPayload(host) {
  const parent = listedParentHost(host);
  const list = findCoveringList(host) || (parent ? findCoveringList(parent) : null);
  return {
    listed: !!list,
    listedParent: !!parent,
    listedParentRule: parent ? listedParentRule(host) : "",
    listName: list ? listLabel(list) : ""
  };
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

function decideProxySync(host, tabId) {
  const route = ListUpdate.fetchRouteOverride(host, tabId, fetchDirectHosts, fetchProxyHosts);
  if (route === "direct") return { type: "direct" };
  if (route === "proxy") return ffProxy;
  if (!extensionEnabled) return { type: "direct" };
  if (isDirectHost(host)) return { type: "direct" };
  if (isProxiedHost(host)) return ffProxy;
  return null;
}

const pendingDns = new Map();

function resolveDns(host) {
  const now = Date.now();
  const hit = dnsCache.get(host);
  if (hit && now - hit.t < 60000) return Promise.resolve(hit.addrs);
  if (pendingDns.has(host)) return pendingDns.get(host);

  const promise = browser.dns.resolve(host).then(rec => {
    const addrs = (rec && rec.addresses) || [];
    if (dnsCache.size >= 512) dnsCache.delete(dnsCache.keys().next().value);
    dnsCache.set(host, { t: Date.now(), addrs });
    return addrs;
  }).catch(() => {
    dnsCache.set(host, { t: Date.now(), addrs: [] });
    return [];
  }).finally(() => {
    pendingDns.delete(host);
  });

  pendingDns.set(host, promise);
  return promise;
}

function onProxyRequest(requestInfo) {
  if (!initialized) {
    return initPromise.then(() => handleProxyRequest(requestInfo));
  }
  return handleProxyRequest(requestInfo);
}

function handleProxyRequest(requestInfo) {
  if (isOwnPage(requestInfo && requestInfo.url)) return { type: "direct" };
  let host = "";
  try { host = new URL(requestInfo.url).hostname.toLowerCase(); } catch (e) { return { type: "direct" }; }
  if (!host) return { type: "direct" };
  const tabId = requestInfo.tabId;
  const sync = decideProxySync(host, tabId);
  if (sync) {
    rememberTabHost(tabId, host, sync.type !== "direct");
    scheduleBadge(tabId);
    return sync;
  }
  if (!hasIps || PacParse.IPV4_RE.test(host) || host.indexOf(":") >= 0) {
    rememberTabHost(tabId, host, false);
    return { type: "direct" };
  }
  return resolveDns(host).then(addrs => {
    for (let i = 0; i < addrs.length; i++) {
      const hit = decideProxySync(String(addrs[i] || "").replace(/^\[|\]$/g, ""), tabId);
      if (hit) {
        rememberTabHost(tabId, host, hit.type !== "direct");
        scheduleBadge(tabId);
        return hit;
      }
    }
    rememberTabHost(tabId, host, false);
    return { type: "direct" };
  });
}

function rememberTabHost(tabId, host, proxied) {
  if (tabId == null || tabId < 0 || !host) return;
  if (!tabHosts[tabId]) tabHosts[tabId] = new Set();
  tabHosts[tabId].add(host);
  if (proxied || hostIsProxied(host)) {
    if (!tabProxied[tabId]) tabProxied[tabId] = new Set();
    tabProxied[tabId].add(host);
  }
  scheduleBadge(tabId);
}

function isOwnPage(url) {
  const s = String(url || "");
  if (!s) return false;
  try {
    const base = browser.runtime.getURL("");
    return !!(base && s.indexOf(base) === 0);
  } catch (e) {
    return false;
  }
}

function seedTabUrl(tabId, url) {
  if (tabId == null || tabId < 0 || !url || isOwnPage(url)) return;
  let host = "";
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return;
    host = parsed.hostname.toLowerCase();
  } catch (e) { return; }
  rememberTabHost(tabId, host, false);
}

function recountTabProxied() {
  Object.keys(tabHosts).forEach(id => {
    const tabId = Number(id);
    const next = new Set();
    tabHosts[tabId].forEach(h => {
      if (hostIsProxied(h)) next.add(h);
    });
    tabProxied[tabId] = next;
    delete badgeText[tabId];
    scheduleBadge(tabId);
  });
  browser.tabs.query({}).then(tabs => {
    tabs.forEach(tab => seedTabUrl(tab.id, tab.url));
  }).catch(() => {});
}

function toolbarIconOn() {
  return !!(extensionEnabled && proxyConfig && proxyConfig.host);
}

async function syncToolbarIcon() {
  const file = toolbarIconOn() ? "icons/icon_128.png" : "icons/icon_off_128.png";
  try {
    await browser.action.setIcon({ path: file });
  } catch (e) {}
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
  const text = n ? (n > 99 ? "∞" : String(n)) : "";
  if (badgeText[tabId] === text) return;
  badgeText[tabId] = text;
  try {
    if (!badgeColorsReady) {
      await browser.action.setBadgeBackgroundColor({ color: "#6d6f78" });
      await browser.action.setBadgeTextColor({ color: "#ffffff" });
      badgeColorsReady = true;
    }
    await browser.action.setBadgeText({ tabId, text });
  } catch (e) {}
}

async function queryActiveTab() {
  try {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0]) return tabs[0];
  } catch (e) {}
  try {
    const tabs = await browser.tabs.query({ active: true });
    return (tabs && tabs[0]) || null;
  } catch (e) {
    return null;
  }
}

async function refreshActiveBadge() {
  const tab = await queryActiveTab();
  if (tab) await updateBadge(tab.id);
}

browser.proxy.onRequest.addListener(onProxyRequest, { urls: ALL_WEB_URLS });

const proxyAuthTried = new Set();

try {
  browser.webRequest.onAuthRequired.addListener(
    function (details) {
      if (!details.isProxy) return {};
      if (!proxyConfig.username && !proxyConfig.password) return {};
      const id = details.requestId;
      if (proxyAuthTried.has(id)) return { cancel: true };
      if (proxyAuthTried.size > 200) proxyAuthTried.clear();
      proxyAuthTried.add(id);
      return {
        authCredentials: {
          username: proxyConfig.username || "",
          password: proxyConfig.password || ""
        }
      };
    },
    { urls: ALL_WEB_URLS },
    ["blocking"]
  );
} catch (e) {}

browser.tabs.onRemoved.addListener((tabId) => {
  delete tabHosts[tabId];
  delete tabProxied[tabId];
  delete badgeText[tabId];
  if (badgeWait[tabId]) {
    clearTimeout(badgeWait[tabId]);
    delete badgeWait[tabId];
  }
});

browser.tabs.onActivated.addListener(async (info) => {
  try {
    const tab = await browser.tabs.get(info.tabId);
    seedTabUrl(info.tabId, tab && tab.url);
  } catch (e) {}
  updateBadge(info.tabId);
});
browser.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (change.status === "loading") {
    tabHosts[tabId] = new Set();
    tabProxied[tabId] = new Set();
    delete badgeText[tabId];
    if (change.url) seedTabUrl(tabId, change.url);
    else if (tab && tab.url) seedTabUrl(tabId, tab.url);
    scheduleBadge(tabId);
    return;
  }
  if (change.url) seedTabUrl(tabId, change.url);
  else if (change.status === "complete" && tab && tab.url) seedTabUrl(tabId, tab.url);
  scheduleBadge(tabId);
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

let listPersistSkipRebuild = 0;

async function persistProxyLists(opts) {
  if (opts && opts.skipRebuild) listPersistSkipRebuild++;
  try {
    await browser.storage.local.set({ proxyLists });
  } catch (e) {
    if (opts && opts.skipRebuild) listPersistSkipRebuild = Math.max(0, listPersistSkipRebuild - 1);
    throw e;
  }
}

async function persistListUpdateError(existingId, err) {
  if (existingId == null) return;
  const current = proxyLists.find(x => x.id === existingId);
  if (!current) return;
  markListUpdateError(current, err);
  await persistProxyLists({ skipRebuild: true });
}

function ingestRemoteSync(url, text) {
  return ListIngest.ingestRemote(url, text);
}

function ingestRemoteAsync(url, text) {
  return new Promise((resolve, reject) => {
    let worker;
    try {
      worker = new Worker(browser.runtime.getURL("list-ingest-worker.js"));
    } catch (e) {
      try { resolve(ingestRemoteSync(url, text)); }
      catch (err) { reject(err); }
      return;
    }
    const timer = setTimeout(() => {
      try { worker.terminate(); } catch (e) {}
      reject(new Error("Разбор списка превысил время ожидания"));
    }, 60000);
    const finish = fn => {
      clearTimeout(timer);
      try { worker.terminate(); } catch (e) {}
      fn();
    };
    worker.onmessage = e => {
      const data = e.data || {};
      if (data.ok) finish(() => resolve(data.item));
      else finish(() => reject(new Error(data.error || "Ошибка разбора списка")));
    };
    worker.onerror = e => {
      finish(() => reject(new Error((e && e.message) || "Ошибка разбора списка")));
    };
    try {
      worker.postMessage({ url, text });
    } catch (e) {
      finish(() => {
        try { resolve(ingestRemoteSync(url, text)); }
        catch (err) { reject(err); }
      });
    }
  });
}

async function fetchAndStoreList(url, existingId, msg) {
  url = String(url || "").trim();
  if (!url.startsWith("http")) throw new Error("Введите корректный URL");
  if (findListByUrl(url, existingId)) throw new Error("Список добавить нельзя, он уже существует");
  const existing = existingId != null ? proxyLists.find(x => x.id === existingId) : null;
  const meta = listMeta(msg || {}, existing);
  try {
    const text = await withFetchRoute(url, meta.viaProxy, async () => {
      const r = await fetch(url, {
        cache: "no-store",
        headers: { Accept: "application/x-ns-proxy-autoconfig, text/plain, application/javascript, */*" },
        signal: AbortSignal.timeout(45000)
      });
      const body = await r.text();
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${body.replace(/\s+/g, " ").trim().slice(0, 160)}`);
      return body;
    });
    const item = await ingestRemoteAsync(url, text);
    const stored = ListUpdate.commitFetchedList(proxyLists, item, meta, url, existingId, Date.now());
    rebuildMaps();
    await persistProxyLists({ skipRebuild: true });
    return stored;
  } catch (e) {
    await persistListUpdateError(existingId, e);
    throw e;
  }
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

let listUpdateBusy = false;

function markListUpdateError(list, err) {
  ListUpdate.markFailure(list, err, Date.now());
}

async function updateListedLists(all) {
  if (!proxyLists.length) return { updated: 0, failed: 0 };
  const now = Date.now();
  const ids = proxyLists.filter(list => list.url && (all || ListUpdate.isDue(list, now))).map(list => list.id);
  let updated = 0;
  let failed = 0;
  for (const id of ids) {
    const list = proxyLists.find(x => x.id === id);
    if (!list || !list.url) continue;
    if (!all && !ListUpdate.isDue(list, Date.now())) continue;
    try {
      await fetchAndStoreList(list.url, list.id, list);
      updated++;
    } catch (e) {
      failed++;
    }
  }
  if (updated || all) await refreshActiveBadge();
  return { updated, failed };
}

async function withListUpdateLock(fn) {
  if (listUpdateBusy) return { updated: 0, failed: 0, skipped: true };
  listUpdateBusy = true;
  try { return await fn(); }
  finally { listUpdateBusy = false; }
}

async function updateAllLists() {
  return withListUpdateLock(() => updateListedLists(true));
}

async function updateDueLists() {
  return withListUpdateLock(() => updateListedLists(false));
}

async function scheduleListUpdates() {
  try {
    const when = ListUpdate.alarmWhen(proxyLists, Date.now());
    if (!when) {
      await browser.alarms.clear("updateLists");
      return;
    }
    const existing = await browser.alarms.get("updateLists");
    if (existing && !existing.periodInMinutes && Math.abs(existing.scheduledTime - when) < 15000) return;
    await browser.alarms.create("updateLists", { when });
  } catch (e) {}
}

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "fetchList") {
    fetchAndStoreList(msg.url, msg.id, msg)
      .then(() => sendResponse({ success: true }))
      .catch(e => sendResponse({ success: false, error: String(e.message || e) }));
    return true;
  }
  if (msg.action === "saveListMeta") {
    saveListMeta(msg)
      .then(() => rebuildMaps())
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
    fetchAndStoreList(list.url, list.id, list)
      .then(() => sendResponse({ success: true }))
      .catch(e => sendResponse({ success: false, error: String(e.message || e) }));
    return true;
  }
  if (msg.action === "refreshLists") {
    updateAllLists()
      .then(res => sendResponse({ success: true, updated: res.updated, failed: res.failed }))
      .catch(e => sendResponse({ success: false, error: String(e.message || e) }));
    return true;
  }
  if (msg.action === "coverInfoMany") {
    const hosts = Array.isArray(msg.hosts) ? msg.hosts : [];
    const covers = {};
    hosts.forEach(h => {
      const host = normalizeRule(h).replace(/^\*\./, "");
      if (!host || covers[host]) return;
      covers[host] = coverPayload(host);
    });
    sendResponse({ covers });
    return true;
  }
  if (msg.action === "coverInfo") {
    const host = normalizeRule(msg.host || "").replace(/^\*\./, "");
    sendResponse(coverPayload(host));
    return true;
  }
  if (msg.action === "getTabDomains") {
    const domains = tabHosts[msg.tabId] ? Array.from(tabHosts[msg.tabId]) : [];
    sendResponse({ domains: domains.sort() });
    return true;
  }
  if (msg.action === "checkProxyControl") {
    if (browser.proxy && browser.proxy.settings && typeof browser.proxy.settings.get === "function") {
      browser.proxy.settings.get({}).then(details => {
        const level = (details && details.levelOfControl) || "";
        sendResponse({ levelOfControl: level, isBlocked: level === "controlled_by_other_extensions" });
      }).catch(() => {
        sendResponse({ levelOfControl: "", isBlocked: false });
      });
    } else {
      sendResponse({ levelOfControl: "", isBlocked: false });
    }
    return true;
  }
});

browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== "updateLists") return;
  updateDueLists().finally(scheduleListUpdates);
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
  if (changes.proxyLists) {
    proxyLists = changes.proxyLists.newValue || [];
    if (listPersistSkipRebuild > 0) listPersistSkipRebuild--;
    else need = true;
    scheduleListUpdates();
  }
  if (changes.extensionEnabled) {
    extensionEnabled = !!changes.extensionEnabled.newValue && !!(proxyConfig && proxyConfig.host);
    need = true;
  }
  if (need) {
    rebuildMaps();
    await syncToolbarIcon();
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

let initialized = false;

async function initBackground() {
  const res = await browser.storage.local.get(["proxyConfig", "proxyServers", "proxyRules", "directRules", "proxyLists", "extensionEnabled"]);
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
  rebuildMaps();
  await syncToolbarIcon();
  await refreshActiveBadge();
  initialized = true;
  if (stale) await updateAllLists();
  else await updateDueLists();
  await scheduleListUpdates();
}

const initPromise = initBackground();
