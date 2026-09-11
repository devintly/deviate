"use strict";

importScripts("pac-parse.js", "list-update.js", "list-ingest.js");

let proxyConfig = { type: "socks", host: "", port: 0, username: "", password: "" };
let proxyServers = [];
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
let viaProxyHosts = {};

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

function addHostRules(rules, exact, suffix, ipExact) {
  (rules || []).forEach(r => {
    const n = normalizeRule(r);
    if (!n) return;
    if (PacParse.IPV4_RE.test(n) || n.indexOf(":") >= 0) {
      ipExact[n] = 1;
    } else if (n.startsWith("*.")) {
      const d = n.slice(2);
      exact[d] = 1;
      suffix[d] = 1;
    } else {
      exact[n] = 1;
    }
  });
}

function addListTargets(list, exact, suffix, ipExact, cidrs) {
  (list.domains || []).forEach(d => {
    const n = normalizeRule(d);
    if (!n) return;
    if (n.startsWith("*.")) {
      const dom = n.slice(2);
      exact[dom] = 1;
      suffix[dom] = 1;
    } else {
      exact[n] = 1;
    }
  });
  (list.ips || []).forEach(ip => {
    ip = String(ip || "").trim();
    if (PacParse.IPV4_RE.test(ip)) ipExact[ip] = 1;
  });
  if (list.cidrs && list.cidrs.length) {
    const compiled = PacParse.compileCidrs(list.cidrs);
    for (let i = 0; i < compiled.length; i++) cidrs.push(compiled[i]);
  }
}

function rebuildMaps() {
  const nextPE = {}, nextPS = {}, nextDE = {}, nextDS = {};
  const nextPIp = {}, nextDIp = {}, nextPCidr = [];
  const nextPPac = [];
  const nextCompiledLists = [];
  const nextViaProxy = {};

  addHostRules(proxyRules, nextPE, nextPS, nextPIp);
  addHostRules(directRules, nextDE, nextDS, nextDIp);

  proxyLists.forEach(list => {
    if (list.viaProxy && list.url) {
      try {
        const u = new URL(list.url);
        if (u.hostname) nextViaProxy[u.hostname.toLowerCase()] = 1;
      } catch (_) {}
    }

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
  viaProxyHosts = nextViaProxy;
}

function pacProxyString(cfg) {
  if (!cfg || !cfg.host || !cfg.port) return "DIRECT";
  const type = String(cfg.type || "socks").toLowerCase();
  const host = String(cfg.host).trim();
  const port = Number(cfg.port);
  if (type === "socks" || type === "socks5") {
    return `SOCKS5 ${host}:${port}; SOCKS ${host}:${port}; DIRECT`;
  }
  if (type === "https") {
    return `HTTPS ${host}:${port}; DIRECT`;
  }
  return `PROXY ${host}:${port}; DIRECT`;
}

function generatePacScript(proxyStr, dExact, dSuffix, dIp, pExact, pSuffix, pIp, pCidr, pacLists, viaProxy) {
  const serializedPacLists = (pacLists || []).map(p => ({
    extra: p.extraMap || {},
    packed: p.packed || null,
    patterns: p.patterns || null,
    patKeys: p.patKeys || null,
    threePart: p.threePart || ""
  }));

  return `var PROXY = ${JSON.stringify(proxyStr)};
var dE = ${JSON.stringify(dExact)};
var dS = ${JSON.stringify(dSuffix)};
var dIp = ${JSON.stringify(dIp)};
var pE = ${JSON.stringify(pExact)};
var pS = ${JSON.stringify(pSuffix)};
var pIp = ${JSON.stringify(pIp)};
var pCidr = ${JSON.stringify(pCidr)};
var viaProxy = ${JSON.stringify(viaProxy)};
var rawPac = ${JSON.stringify(serializedPacLists)};

function indexPacked(packed) {
  var idx = {};
  if (!packed) return idx;
  var zones = Object.keys(packed);
  for (var z = 0; z < zones.length; z++) {
    var zone = zones[z];
    var byLen = packed[zone];
    if (!byLen) continue;
    var names = idx[zone] = {};
    var lens = Object.keys(byLen);
    for (var l = 0; l < lens.length; l++) {
      var len = +lens[l];
      var chunk = byLen[lens[l]];
      if (!len || typeof chunk !== "string") continue;
      for (var p = 0; p + len <= chunk.length; p += len) {
        names[chunk.substr(p, len)] = 1;
      }
    }
  }
  return idx;
}

var pacLists = rawPac.map(function(p) {
  var threeRe = null;
  if (p.threePart) {
    try { threeRe = new RegExp("\\\\.(" + p.threePart + ")\\\\.[^.]+$"); } catch (e) {}
  }
  return {
    extra: p.extra || {},
    patterns: p.patterns,
    patKeys: p.patKeys,
    threeRe: threeRe,
    idx: indexPacked(p.packed)
  };
});

function matchSuffix(host, map) {
  var dot = host.indexOf(".");
  while (dot !== -1) {
    if (map[host.substring(dot + 1)]) return true;
    dot = host.indexOf(".", dot + 1);
  }
  return false;
}

function ipToInt(ip) {
  var p = (ip || "").split(".");
  if (p.length !== 4) return 0;
  return ((Number(p[0]) << 24) >>> 0) + (Number(p[1]) << 16) + (Number(p[2]) << 8) + Number(p[3]);
}

function matchCidrs(ipInt, cidrs) {
  for (var i = 0; i < cidrs.length; i++) {
    var c = cidrs[i];
    if ((ipInt & c[1]) === c[0]) return true;
  }
  return false;
}

function applyPatterns(str, patterns, keys) {
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    if (str.indexOf(k) >= 0) str = str.split(k).join(patterns[k]);
  }
  return str;
}

function toShortHost(host, threeRe) {
  if (host.charAt(host.length - 1) === ".") host = host.slice(0, -1);
  if (threeRe && threeRe.test(host)) host = host.replace(/(.+)\\.([^.]+\\.[^.]+\\.[^.]+$)/, "$2");
  else host = host.replace(/(.+)\\.([^.]+\\.[^.]+$)/, "$2");
  if (host.indexOf("www.") === 0) host = host.slice(4);
  return host;
}

function matchPac(host, p) {
  if (p.extra && p.extra[host]) return true;
  if (p.idx) {
    var shost = toShortHost(host, p.threeRe);
    var dot = shost.lastIndexOf(".");
    if (dot >= 1) {
      var name = p.patterns ? applyPatterns(shost.slice(0, dot), p.patterns, p.patKeys) : shost.slice(0, dot);
      var names = p.idx[shost.slice(dot + 1)];
      if (names && names[name]) return true;
    }
  }
  return false;
}

function FindProxyForURL(url, host) {
  if (!host) return "DIRECT";
  host = host.toLowerCase();
  if (host.charCodeAt(host.length - 1) === 46) host = host.slice(0, -1);
  if (host.charCodeAt(0) === 46) host = host.slice(1);

  if (dE[host] || dIp[host] || matchSuffix(host, dS)) return "DIRECT";
  if (viaProxy[host]) return PROXY;
  if (pE[host] || pIp[host] || matchSuffix(host, pS)) return PROXY;

  if (pCidr && pCidr.length && /^(?:\\d{1,3}\\.){3}\\d{1,3}$/.test(host)) {
    if (matchCidrs(ipToInt(host), pCidr)) return PROXY;
  }

  if (pacLists && pacLists.length) {
    for (var i = 0; i < pacLists.length; i++) {
      if (matchPac(host, pacLists[i])) return PROXY;
    }
  }

  return "DIRECT";
}`;
}

async function applyProxySettings() {
  if (!extensionEnabled || !proxyConfig || !proxyConfig.host || Number(proxyConfig.port) <= 0) {
    return new Promise(resolve => {
      chrome.proxy.settings.clear({ scope: "regular" }, () => {
        chrome.storage.local.set({ lastProxyError: "" });
        syncToolbarIcon();
        refreshActiveBadge();
        resolve();
      });
    });
  }

  const proxyStr = pacProxyString(proxyConfig);
  const pacCode = generatePacScript(proxyStr, dE, dS, dIp, pE, pS, pIp, pCidr, pPac, viaProxyHosts);

  return new Promise(resolve => {
    chrome.proxy.settings.set({
      value: {
        mode: "pac_script",
        pacScript: {
          data: pacCode,
          mandatory: false
        }
      },
      scope: "regular"
    }, () => {
      if (chrome.runtime.lastError) {
        const err = chrome.runtime.lastError.message || "Ошибка применения PAC-скрипта";
        chrome.storage.local.set({ lastProxyError: err });
      } else {
        chrome.storage.local.set({ lastProxyError: "" });
      }
      syncToolbarIcon();
      refreshActiveBadge();
      resolve();
    });
  });
}

// Proxy authentication
chrome.webRequest.onAuthRequired.addListener(
  (details, callbackFn) => {
    ensureInit().then(() => {
      if (details.isProxy && proxyConfig.username && proxyConfig.password) {
        callbackFn({
          authCredentials: {
            username: proxyConfig.username,
            password: proxyConfig.password
          }
        });
      } else {
        callbackFn({});
      }
    }).catch(() => callbackFn({}));
  },
  { urls: ["<all_urls>"] },
  ["asyncBlocking"]
);

function matchSuffixInMap(host, map) {
  let dot = host.indexOf(".");
  while (dot !== -1) {
    if (map[host.substring(dot + 1)]) return true;
    dot = host.indexOf(".", dot + 1);
  }
  return false;
}

function isHostProxied(host) {
  if (!host) return false;
  host = host.toLowerCase();
  if (host.charCodeAt(host.length - 1) === 46) host = host.slice(0, -1);
  if (host.charCodeAt(0) === 46) host = host.slice(1);

  if (dE[host] || dIp[host] || matchSuffixInMap(host, dS)) return false;
  if (viaProxyHosts[host]) return true;
  if (pE[host] || pIp[host] || matchSuffixInMap(host, pS)) return true;

  if (pCidr && pCidr.length && PacParse.IPV4_RE.test(host)) {
    if (PacParse.matchIpLiteral(host, pCidr)) return true;
  }

  for (let i = 0; i < compiledLists.length; i++) {
    const cl = compiledLists[i];
    if (cl.pac && PacParse.matchPacHost(host, cl.pac)) return true;
  }
  return false;
}

function recordTabHost(tabId, host) {
  if (tabId == null || tabId < 0 || !host) return;
  if (PacParse.IPV4_RE.test(host) || host.indexOf(":") >= 0) return;
  host = host.toLowerCase();
  let s = tabHosts[tabId];
  if (!s) { s = new Set(); tabHosts[tabId] = s; }
  if (s.size < 200) s.add(host);

  if (extensionEnabled && isHostProxied(host)) {
    let p = tabProxied[tabId];
    if (!p) { p = new Set(); tabProxied[tabId] = p; }
    p.add(host);
    scheduleBadge(tabId);
  }
}

function recountTabProxied() {
  Object.keys(tabHosts).forEach(id => {
    const tabId = Number(id);
    const next = new Set();
    const hosts = tabHosts[tabId];
    if (hosts && extensionEnabled) {
      hosts.forEach(h => {
        if (isHostProxied(h)) next.add(h);
      });
    }
    tabProxied[tabId] = next;
    scheduleBadge(tabId);
  });
}

// Request observer for badge and tab hosts tracking
chrome.webRequest.onBeforeRequest.addListener(
  details => {
    if (details.tabId == null || details.tabId < 0) return;
    try {
      const u = new URL(details.url);
      const host = u.hostname;
      if (!host) return;
      recordTabHost(details.tabId, host);
    } catch (_) {}
  },
  { urls: ["http://*/*", "https://*/*", "ws://*/*", "wss://*/*"] }
);

function ownPageBase() {
  try { return chrome.runtime.getURL(""); } catch (_) { return ""; }
}
function isOwnPage(url) {
  const s = String(url || "");
  if (!s) return false;
  const base = ownPageBase();
  return !!(base && s.indexOf(base) === 0);
}
function isWebTab(tab) {
  if (!tab || isOwnPage(tab.url)) return false;
  try {
    const p = new URL(tab.url).protocol;
    return p === "http:" || p === "https:";
  } catch (_) {
    return false;
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && isWebTab(tab)) {
    tabHosts[tabId] = new Set();
    tabProxied[tabId] = new Set();
    scheduleBadge(tabId);
  }
});

chrome.tabs.onRemoved.addListener(tabId => {
  delete tabHosts[tabId];
  delete tabProxied[tabId];
  delete badgeWait[tabId];
});

chrome.tabs.onActivated.addListener(activeInfo => {
  scheduleBadge(activeInfo.tabId);
});

const badgeWait = {};
let badgeColorsReady = false;

function scheduleBadge(tabId) {
  if (tabId == null || tabId < 0 || badgeWait[tabId]) return;
  badgeWait[tabId] = true;
  setTimeout(() => {
    delete badgeWait[tabId];
    flushBadge(tabId);
  }, 100);
}

async function flushBadge(tabId) {
  const set = tabProxied[tabId];
  const count = (extensionEnabled && set) ? set.size : 0;
  const text = count > 0 ? (count > 99 ? "99+" : String(count)) : "";
  try {
    if (!badgeColorsReady) {
      await chrome.action.setBadgeBackgroundColor({ color: "#6d6f78" });
      try { await chrome.action.setBadgeTextColor({ color: "#ffffff" }); } catch (_) {}
      badgeColorsReady = true;
    }
    await chrome.action.setBadgeText({ tabId, text });
  } catch (e) {}
}

async function refreshActiveBadge() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0]) scheduleBadge(tabs[0].id);
  } catch (_) {}
}

function toolbarIconOn() {
  return !!(extensionEnabled && proxyConfig && proxyConfig.host);
}

async function syncToolbarIcon() {
  const file = toolbarIconOn() ? "icons/icon_128.png" : "icons/icon_off_128.png";
  try {
    await chrome.action.setIcon({ path: file });
  } catch (e) {}
}

function findListByUrl(url, excludeId) {
  const norm = String(url || "").trim().toLowerCase();
  return proxyLists.find(x => x.id !== excludeId && String(x.url || "").trim().toLowerCase() === norm);
}

function listMeta(src, current) {
  const cur = current || {};
  const name = String(src.name !== undefined ? src.name : (cur.name || "")).trim();
  let intervalHours = Number(src.intervalHours !== undefined ? src.intervalHours : cur.intervalHours);
  if (!Number.isFinite(intervalHours) || intervalHours < 1) intervalHours = 24;
  intervalHours = Math.round(intervalHours);
  const viaProxy = !!(src.viaProxy !== undefined ? src.viaProxy : cur.viaProxy);
  return { name, intervalHours, viaProxy };
}

async function fetchAndStoreList(url, existingId, msg) {
  url = String(url || "").trim();
  if (!url.startsWith("http")) throw new Error("Неверный формат URL");
  if (findListByUrl(url, existingId)) throw new Error("Список с таким URL уже добавлен");
  const existing = existingId != null ? proxyLists.find(x => x.id === existingId) : null;
  const meta = listMeta(msg || {}, existing);
  try {
    const r = await fetch(url, {
      cache: "no-store",
      headers: { Accept: "application/x-ns-proxy-autoconfig, text/plain, application/javascript, */*" },
      signal: AbortSignal.timeout(45000)
    });
    const body = await r.text();
    if (!r.ok) throw new Error(`HTTP ${r.status}: ${body.replace(/\s+/g, " ").trim().slice(0, 160)}`);

    const item = ListIngest.ingestRemote(url, body);
    const stored = ListUpdate.commitFetchedList(proxyLists, item, meta, url, existingId, Date.now());
    rebuildMaps();
    await chrome.storage.local.set({ proxyLists });
    await applyProxySettings();
    return stored;
  } catch (e) {
    if (existingId != null) {
      const idx = proxyLists.findIndex(x => x.id === existingId);
      if (idx >= 0) {
        ListUpdate.markFailure(proxyLists[idx], e, Date.now());
        proxyLists[idx].lastError = proxyLists[idx].updateError;
        await chrome.storage.local.set({ proxyLists });
      }
    }
    throw e;
  }
}

async function saveListMeta(msg) {
  const idx = proxyLists.findIndex(x => x.id === msg.id);
  if (idx < 0) throw new Error("Список не найден");
  const url = String(msg.url || proxyLists[idx].url || "").trim();
  if (!url.startsWith("http")) throw new Error("Неверный формат URL");
  if (findListByUrl(url, msg.id)) throw new Error("Список с таким URL уже добавлен");
  const meta = listMeta(msg, proxyLists[idx]);
  proxyLists[idx].name = meta.name;
  proxyLists[idx].intervalHours = meta.intervalHours;
  proxyLists[idx].viaProxy = meta.viaProxy;
  proxyLists[idx].type = "proxy";
  proxyLists[idx].url = url;
  await chrome.storage.local.set({ proxyLists });
  rebuildMaps();
  await applyProxySettings();
}

let listUpdateBusy = false;

async function updateListedLists(all) {
  let updated = 0, failed = 0;
  for (const list of proxyLists) {
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
    await chrome.alarms.clear("updateLists");
    chrome.alarms.create("updateLists", { periodInMinutes: 30 });
  } catch (e) {}
}

chrome.alarms.onAlarm.addListener(async alarm => {
  if (alarm.name === "updateLists") {
    await ensureInit();
    await updateDueLists();
  }
});

function coverPayload(host) {
  let listedParent = false;
  let listedParentRule = "";
  let listName = "";

  const checkSuffix = (map, name) => {
    let dot = host.indexOf(".");
    while (dot !== -1) {
      const parent = host.substring(dot + 1);
      if (map[parent]) {
        listedParent = true;
        listedParentRule = "*." + parent;
        listName = name;
        return true;
      }
      dot = host.indexOf(".", dot + 1);
    }
    return false;
  };

  let listed = !!(pE[host] || dE[host]);
  if (!listed && checkSuffix(pS, "Пользовательские правила (прокси)")) {}
  else if (!listed && checkSuffix(dS, "Пользовательские правила (напрямую)")) {}
  else if (!listed) {
    for (let i = 0; i < compiledLists.length; i++) {
      const cl = compiledLists[i];
      if (cl.exact[host] || (cl.pac && PacParse.matchPacHost(host, cl.pac))) {
        listed = true;
        listName = cl.list.name || "Удаленный список";
        break;
      }
      if (checkSuffix(cl.suffix, cl.list.name || "Удаленный список")) break;
    }
  }

  return { listed, listedParent, listedParentRule, listName };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  ensureInit().then(() => {
    if (msg.action === "fetchList") {
      fetchAndStoreList(msg.url, msg.id, msg)
        .then(() => sendResponse({ success: true }))
        .catch(e => sendResponse({ success: false, error: String((e && e.message) || e) }));
      return;
    }
    if (msg.action === "saveListMeta") {
      saveListMeta(msg)
        .then(() => sendResponse({ success: true }))
        .catch(e => sendResponse({ success: false, error: String((e && e.message) || e) }));
      return;
    }
    if (msg.action === "refreshList") {
      const list = proxyLists.find(x => x.id === msg.id);
      if (!list) {
        sendResponse({ success: false, error: "Список не найден" });
        return;
      }
      fetchAndStoreList(list.url, list.id, list)
        .then(() => sendResponse({ success: true }))
        .catch(e => sendResponse({ success: false, error: String((e && e.message) || e) }));
      return;
    }
    if (msg.action === "refreshLists") {
      updateAllLists()
        .then(res => sendResponse({ success: true, updated: res.updated, failed: res.failed }))
        .catch(e => sendResponse({ success: false, error: String((e && e.message) || e) }));
      return;
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
      return;
    }
    if (msg.action === "coverInfo") {
      const host = normalizeRule(msg.host || "").replace(/^\*\./, "");
      sendResponse(coverPayload(host));
      return;
    }
    if (msg.action === "getTabDomains") {
      const set = tabHosts[msg.tabId];
      sendResponse({ domains: set ? Array.from(set) : [] });
      return;
    }
    if (msg.action === "updateBadge") {
      refreshActiveBadge().then(() => sendResponse({ ok: true }));
      return;
    }
    if (msg.action === "checkProxyControl") {
      try {
        chrome.proxy.settings.get({ incognito: false }, (details) => {
          const level = (details && details.levelOfControl) || "";
          sendResponse({ levelOfControl: level, isBlocked: level === "controlled_by_other_extensions" });
        });
      } catch (e) {
        sendResponse({ levelOfControl: "", isBlocked: false });
      }
      return;
    }
    sendResponse({});
  }).catch(e => {
    sendResponse({ success: false, error: String((e && e.message) || e) });
  });

  return true;
});

chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area !== "local") return;
  await ensureInit();
  let needRebuild = false;

  if (changes.proxyServers) {
    proxyServers = Array.isArray(changes.proxyServers.newValue) ? changes.proxyServers.newValue : [];
    proxyConfig = configFromServers(proxyServers);
    needRebuild = true;
  }
  if (changes.proxyConfig && !changes.proxyServers) {
    proxyConfig = Object.assign({}, proxyConfig, changes.proxyConfig.newValue || {});
    needRebuild = true;
  }
  if (changes.proxyRules) {
    proxyRules = Array.isArray(changes.proxyRules.newValue) ? changes.proxyRules.newValue : [];
    needRebuild = true;
  }
  if (changes.directRules) {
    directRules = Array.isArray(changes.directRules.newValue) ? changes.directRules.newValue : [];
    needRebuild = true;
  }
  if (changes.proxyLists) {
    proxyLists = Array.isArray(changes.proxyLists.newValue) ? changes.proxyLists.newValue : [];
    needRebuild = true;
  }
  if (changes.extensionEnabled) {
    extensionEnabled = !!changes.extensionEnabled.newValue;
    needRebuild = true;
  }

  if (needRebuild) {
    rebuildMaps();
    recountTabProxied();
    await applyProxySettings();
  }
});

let initialized = false;
let initPromise = null;

async function initBackground() {
  const res = await chrome.storage.local.get([
    "proxyConfig",
    "proxyServers",
    "proxyRules",
    "directRules",
    "proxyLists",
    "extensionEnabled"
  ]);

  const fallback = res.proxyConfig || { type: "socks", host: "", port: 0, username: "", password: "" };
  proxyServers = migrateProxyServers(res.proxyServers, fallback);
  proxyConfig = configFromServers(proxyServers);
  proxyRules = Array.isArray(res.proxyRules) ? res.proxyRules : [];
  directRules = Array.isArray(res.directRules) ? res.directRules : [];
  proxyLists = Array.isArray(res.proxyLists) ? res.proxyLists : [];
  extensionEnabled = res.extensionEnabled === undefined ? true : !!res.extensionEnabled;

  const persist = {};
  if (!res.proxyServers || !res.proxyServers.length) persist.proxyServers = proxyServers;
  if (res.extensionEnabled === undefined) persist.extensionEnabled = extensionEnabled;
  if (Object.keys(persist).length) await chrome.storage.local.set(persist);

  rebuildMaps();
  recountTabProxied();
  await applyProxySettings();
  initialized = true;
  await updateDueLists();
  await scheduleListUpdates();
}

function ensureInit() {
  if (!initPromise) initPromise = initBackground();
  return initPromise;
}

ensureInit();
