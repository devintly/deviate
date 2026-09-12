const ALL_WEB_URLS = ["http://*/*", "https://*/*", "ws://*/*", "wss://*/*"];

let proxyConfig = ProxyConfig.emptyConfig();
let proxyServers = [];
let proxyRules = [];
let directRules = [];
let proxyLists = [];
let extensionEnabled = false;
let disabledByConflict = false;
let maps = HostRules.rebuildMaps([], [], []);
let hasIps = false;
let ffProxy = { type: "direct" };

const tabHosts = {};
const tabProxied = {};
const tabApex = {};
const dnsCache = new Map();
const pendingDns = new Map();
const fetchProxyHosts = {};
const fetchDirectHosts = {};
const badgeWait = {};
const badgeTextCache = {};
const proxyAuthTried = new Set();
let badgeColorsReady = false;
let listUpdateQueue = Promise.resolve();
let initialized = false;
let badgeRecountGeneration = 0;

function sessionAvailable() {
  try {
    return !!(browser.storage && browser.storage.session && typeof browser.storage.session.get === "function");
  } catch (_) {
    return false;
  }
}

let sessionSaveTimer = null;
function persistTabHostsSession() {
  if (!sessionAvailable()) return;
  if (sessionSaveTimer) return;
  sessionSaveTimer = setTimeout(async () => {
    sessionSaveTimer = null;
    try {
      const obj = {};
      const apexObj = {};
      Object.keys(tabHosts).forEach(id => {
        const s = tabHosts[id];
        if (s && s.size) obj[id] = Array.from(s);
        if (tabApex[id]) apexObj[id] = tabApex[id];
      });
      await browser.storage.session.set({ tabHosts: obj, tabApex: apexObj });
    } catch (_) {}
  }, 300);
}

function applyMaps(next) {
  maps = next;
  ffProxy = PacParse.userProxyToFirefox(proxyConfig);
  hasIps = HostRules.hasIpRules(maps);
}

function rebuildMaps() {
  applyMaps(HostRules.rebuildMaps(proxyRules, directRules, proxyLists));
  recountTabProxied();
}

function ownPageBase() {
  try { return browser.runtime.getURL(""); } catch (_) { return ""; }
}

function hostIsProxied(host) {
  return HostRules.hostIsProxied(host, extensionEnabled, maps, false);
}

function decideProxySync(host, tabId) {
  const route = ListUpdate.fetchRouteOverride(host, tabId, fetchDirectHosts, fetchProxyHosts);
  if (route === "direct") return { type: "direct" };
  if (route === "proxy") return ffProxy;
  if (!extensionEnabled) return { type: "direct" };
  if (HostRules.isDirectHost(host, maps)) return { type: "direct" };
  if (HostRules.isProxiedHost(host, maps)) return ffProxy;
  return null;
}

function resetTabForSite(tabId, apex, url) {
  if (tabId == null || tabId < 0) return;
  tabHosts[tabId] = new Set();
  tabProxied[tabId] = new Set();
  delete badgeTextCache[tabId];
  if (apex) tabApex[tabId] = apex;
  else delete tabApex[tabId];
  if (url) seedTabUrl(tabId, url);
  scheduleBadge(tabId);
  persistTabHostsSession();
}

function rememberTabHost(tabId, host, proxied) {
  if (tabId == null || tabId < 0 || !host || HostRules.isIgnoredHost(host)) return;
  const canon = HostRules.canonHost(host);
  if (!canon) return;
  const existing = tabHosts[tabId];
  const alreadyKnown = existing && existing.has(canon);
  const stored = HostRules.rememberHost(tabHosts, tabId, canon);
  if (!stored) return;
  let changed = !alreadyKnown;
  if (proxied || hostIsProxied(stored)) {
    if (!tabProxied[tabId]) tabProxied[tabId] = new Set();
    if (!tabProxied[tabId].has(stored)) {
      tabProxied[tabId].add(stored);
      changed = true;
    }
  }
  if (changed) {
    scheduleBadge(tabId);
    persistTabHostsSession();
  }
}

function getUrlHost(url) {
  if (!url) return "";
  try {
    const p = new URL(url);
    if (p.protocol !== "http:" && p.protocol !== "https:") return "";
    return p.hostname.toLowerCase();
  } catch (_) {
    return "";
  }
}

function seedTabUrl(tabId, url) {
  if (tabId == null || tabId < 0 || !url || HostRules.isOwnPage(url, ownPageBase())) return;
  const host = getUrlHost(url);
  if (!host || HostRules.isIgnoredHost(host)) return;
  const apex = HostRules.apexDomain(host);
  if (!tabApex[tabId]) tabApex[tabId] = apex;
  else if (apex && tabApex[tabId] && apex !== tabApex[tabId]) return;
  rememberTabHost(tabId, host, false);
}

function recountTabProxied() {
  const generation = ++badgeRecountGeneration;
  Object.keys(tabHosts).forEach(id => {
    const tabId = Number(id);
    const next = new Set();
    const unresolved = [];
    (tabHosts[tabId] || []).forEach(h => {
      if (hostIsProxied(h)) next.add(h);
      else if (extensionEnabled && hasIps && !HostRules.isDirectHost(h, maps)) unresolved.push(h);
    });
    tabProxied[tabId] = next;
    delete badgeTextCache[tabId];
    scheduleBadge(tabId);
    unresolved.forEach(host => {
      resolveDns(host).then(addresses => {
        if (generation !== badgeRecountGeneration || !extensionEnabled || !tabHosts[tabId] || !tabHosts[tabId].has(host)) return;
        const proxied = addresses.some(ip => {
          const value = String(ip || "").replace(/^\[|\]$/g, "");
          return !HostRules.isDirectHost(value, maps) && HostRules.isProxiedHost(value, maps);
        });
        if (proxied) {
          tabProxied[tabId].add(host);
          delete badgeTextCache[tabId];
          scheduleBadge(tabId);
        }
      });
    });
  });
}

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
  }).finally(() => pendingDns.delete(host));
  pendingDns.set(host, promise);
  return promise;
}

function handleProxyRequest(requestInfo) {
  if (HostRules.isOwnPage(requestInfo && requestInfo.url, ownPageBase())) return { type: "direct" };
  let host = "", u = null;
  try {
    u = new URL(requestInfo.url);
    host = u.hostname.toLowerCase();
  } catch (_) { return { type: "direct" }; }
  if (!host) return { type: "direct" };

  if (host === "cp.cloudflare.com") {
    const probeId = u.searchParams.get("__deviate_probe");
    if (probeId) {
      const target = proxyServers.find(p => String(p.id) === String(probeId));
      if (target && target.host && target.port) return PacParse.userProxyToFirefox(target);
      return { type: "http", host: "127.0.0.1", port: 0 };
    }
  }

  const tabId = requestInfo.tabId;
  if (requestInfo.type === "main_frame" && tabId != null && tabId >= 0 && !HostRules.isIgnoredHost(host)) {
    const navApex = HostRules.apexDomain(host);
    if (navApex && tabApex[tabId] && navApex !== tabApex[tabId]) {
      resetTabForSite(tabId, navApex, requestInfo.url);
    } else if (!tabApex[tabId] && navApex) {
      tabApex[tabId] = navApex;
    }
  }
  const sync = decideProxySync(host, tabId);
  if (sync) {
    rememberTabHost(tabId, host, sync.type !== "direct");
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
        return hit;
      }
    }
    rememberTabHost(tabId, host, false);
    return { type: "direct" };
  });
}

function onProxyRequest(requestInfo) {
  if (!initialized) return initPromise.then(() => handleProxyRequest(requestInfo));
  return handleProxyRequest(requestInfo);
}

async function syncToolbarIcon() {
  try {
    await browser.action.setIcon({ path: ProxyConfig.iconPaths(ProxyConfig.toolbarIconOn(extensionEnabled, proxyConfig)) });
  } catch (_) {}
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
  const text = ProxyConfig.badgeText(n);
  if (badgeTextCache[tabId] === text) return;
  badgeTextCache[tabId] = text;
  try {
    if (!badgeColorsReady) {
      await browser.action.setBadgeBackgroundColor({ color: "#6d6f78" });
      await browser.action.setBadgeTextColor({ color: "#ffffff" });
      badgeColorsReady = true;
    }
    await browser.action.setBadgeText({ tabId, text });
  } catch (_) {}
}

async function queryActiveTab() {
  try {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0]) return tabs[0];
  } catch (_) {}
  try {
    const tabs = await browser.tabs.query({ active: true });
    return (tabs && tabs[0]) || null;
  } catch (_) {
    return null;
  }
}

async function refreshActiveBadge() {
  const tab = await queryActiveTab();
  if (tab) await updateBadge(tab.id);
}

browser.proxy.onRequest.addListener(onProxyRequest, { urls: ALL_WEB_URLS });

try {
  browser.webRequest.onAuthRequired.addListener(
    details => {
      if (!details.isProxy) return {};
      const ch = details.challenger || {};
      const srv = ProxyConfig.findAuthServer(proxyServers, proxyConfig, ch.host, ch.port);
      if (!srv) return {};
      const id = details.requestId;
      if (proxyAuthTried.has(id)) return { cancel: true };
      if (proxyAuthTried.size > 200) proxyAuthTried.clear();
      proxyAuthTried.add(id);
      return { authCredentials: { username: srv.username, password: srv.password } };
    },
    { urls: ALL_WEB_URLS },
    ["blocking"]
  );
} catch (_) {}

browser.tabs.onRemoved.addListener(tabId => {
  delete tabHosts[tabId];
  delete tabProxied[tabId];
  delete tabApex[tabId];
  delete badgeTextCache[tabId];
  if (badgeWait[tabId]) {
    clearTimeout(badgeWait[tabId]);
    delete badgeWait[tabId];
  }
  persistTabHostsSession();
});

browser.tabs.onActivated.addListener(async info => {
  try {
    const tab = await browser.tabs.get(info.tabId);
    seedTabUrl(info.tabId, tab && tab.url);
  } catch (_) {}
  updateBadge(info.tabId);
});

browser.tabs.onUpdated.addListener((tabId, change, tab) => {
  const explicitUrl = (change && change.url) || (tab && tab.pendingUrl) || "";
  if (explicitUrl) {
    const targetHost = getUrlHost(explicitUrl);
    const targetApex = targetHost ? HostRules.apexDomain(targetHost) : "";
    if (targetApex && tabApex[tabId] && targetApex !== tabApex[tabId]) {
      resetTabForSite(tabId, targetApex, explicitUrl);
      return;
    }
    if (change && change.status === "loading") {
      resetTabForSite(tabId, targetApex || tabApex[tabId] || "", explicitUrl);
      return;
    }
    seedTabUrl(tabId, explicitUrl);
    scheduleBadge(tabId);
    return;
  }

  const status = change && change.status;
  const tabUrl = (tab && tab.url) || "";
  const tabHost = getUrlHost(tabUrl);
  const tabApexVal = tabHost ? HostRules.apexDomain(tabHost) : "";

  if (status === "loading") {
    if (tabApexVal && tabApex[tabId] && tabApexVal !== tabApex[tabId]) {
      return;
    }
    resetTabForSite(tabId, tabApexVal || tabApex[tabId] || "", tabUrl);
    return;
  }

  if (status === "complete") {
    if (tabApexVal && tabApex[tabId] && tabApexVal !== tabApex[tabId]) {
      resetTabForSite(tabId, tabApexVal, tabUrl);
      return;
    }
    if (tabUrl) seedTabUrl(tabId, tabUrl);
    scheduleBadge(tabId);
  }
});

async function withFetchRoute(url, viaProxy, fn) {
  if (viaProxy && (!proxyConfig.host || !(Number(proxyConfig.port) > 0))) {
    throw new Error("Сначала добавьте прокси");
  }
  const bucket = viaProxy ? fetchProxyHosts : fetchDirectHosts;
  bucket["*"] = (bucket["*"] || 0) + 1;
  try { return await fn(); }
  finally {
    bucket["*"]--;
    if (bucket["*"] <= 0) delete bucket["*"];
  }
}

async function persistLists() {
  await browser.storage.local.set({ proxyLists });
}

async function fetchAndStoreList(url, existingId, msg) {
  url = String(url || "").trim();
  if (!ListUpdate.validListUrl(url)) throw new Error("Введите корректный URL");
  if (ListUpdate.findListByUrl(proxyLists, url, existingId)) throw new Error("Список добавить нельзя, он уже существует");
  const existing = existingId != null ? proxyLists.find(x => x.id === existingId) : null;
  const meta = ListUpdate.listMeta(msg || {}, existing);
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
    const item = await ListIngest.ingestRemoteAsync(url, text, browser.runtime.getURL("list-ingest-worker.js"));
    const stored = ListUpdate.commitFetchedList(proxyLists, item, meta, url, existingId, Date.now());
    rebuildMaps();
    await persistLists();
    return stored;
  } catch (e) {
    if (existingId != null) {
      const current = proxyLists.find(x => x.id === existingId);
      if (current) {
        ListUpdate.markFailure(current, e, Date.now());
        await persistLists();
      }
    }
    throw e;
  }
}

async function saveListMeta(msg) {
  const idx = proxyLists.findIndex(x => x.id === msg.id);
  if (idx < 0) throw new Error("Список не найден");
  const url = String(msg.url || proxyLists[idx].url || "").trim();
  if (!ListUpdate.validListUrl(url)) throw new Error("Введите корректный URL");
  if (ListUpdate.findListByUrl(proxyLists, url, msg.id)) throw new Error("Список добавить нельзя, он уже существует");
  const meta = ListUpdate.listMeta(msg, proxyLists[idx]);
  Object.assign(proxyLists[idx], { name: meta.name, intervalHours: meta.intervalHours, viaProxy: meta.viaProxy, enabled: meta.enabled, type: "proxy", url });
  await persistLists();
  rebuildMaps();
}

async function setListEnabled(id, enabled) {
  const list = proxyLists.find(item => item.id === id);
  if (!list) throw new Error("Список не найден");
  list.enabled = !!enabled;
  await persistLists();
  rebuildMaps();
  await scheduleListUpdates();
  if (list.enabled && list.url && ListUpdate.isDue(list, Date.now())) {
    try {
      await fetchAndStoreList(list.url, list.id, list);
    } catch (_) {}
  }
}

async function deleteList(id) {
  const length = proxyLists.length;
  proxyLists = proxyLists.filter(item => item.id !== id);
  if (proxyLists.length === length) throw new Error("Список не найден");
  await persistLists();
  rebuildMaps();
  await scheduleListUpdates();
}

async function updateListedLists(all) {
  if (!proxyLists.length) return { updated: 0, failed: 0 };
  const ids = proxyLists.filter(list => list.url && list.enabled !== false && (all || ListUpdate.isDue(list, Date.now()))).map(list => list.id);
  let updated = 0, failed = 0;
  for (const id of ids) {
    const list = proxyLists.find(x => x.id === id);
    if (!list || !list.url || list.enabled === false) continue;
    if (!all && !ListUpdate.isDue(list, Date.now())) continue;
    try {
      await fetchAndStoreList(list.url, list.id, list);
      updated++;
    } catch (_) {
      failed++;
    }
  }
  if (updated || all) await refreshActiveBadge();
  return { updated, failed };
}

function enqueueListUpdate(fn) {
  const task = listUpdateQueue.then(fn, fn);
  listUpdateQueue = task.catch(() => {});
  return task;
}

function updateAllLists() { return enqueueListUpdate(() => updateListedLists(true)); }
function updateDueLists() { return enqueueListUpdate(() => updateListedLists(false)); }

async function scheduleListUpdates() {
  try {
    const when = ListUpdate.alarmWhen(proxyLists.filter(l => l.enabled !== false), Date.now());
    if (!when) {
      await browser.alarms.clear("updateLists");
      return;
    }
    const existing = await browser.alarms.get("updateLists");
    if (existing && !existing.periodInMinutes && Math.abs(existing.scheduledTime - when) < 15000) return;
    await browser.alarms.create("updateLists", { when });
  } catch (_) {}
}

async function pingServer(server) {
  if (!server || !server.host || !server.port) {
    return { id: server ? server.id : null, success: false, latency: null };
  }
  const probeUrl = `http://cp.cloudflare.com/generate_204?__deviate_probe=${server.id}&_t=${Date.now()}_${Math.random()}`;
  const start = performance.now();
  try {
    await fetch(probeUrl, { cache: "no-store", mode: "no-cors", signal: AbortSignal.timeout(5000) });
    return { id: server.id, success: true, latency: Math.max(1, Math.round(performance.now() - start)) };
  } catch (_) {
    return { id: server.id, success: false, latency: null };
  }
}

async function pingAllServers(serversToPing) {
  const targets = (serversToPing && serversToPing.length ? serversToPing : proxyServers).filter(p => p && p.host && p.port);
  if (!targets.length) return {};
  const results = {};
  (await Promise.all(targets.map(pingServer))).forEach(res => {
    if (res && res.id != null) results[res.id] = { success: res.success, latency: res.latency };
  });
  return results;
}

async function handleConflictControl(level) {
  const isBlocked = level === "controlled_by_other_extensions";
  if (isBlocked) {
    if (extensionEnabled) {
      extensionEnabled = false;
      disabledByConflict = true;
      await browser.storage.local.set({ extensionEnabled: false, disabledByConflict: true });
      await syncToolbarIcon();
      await refreshActiveBadge();
    }
  } else if (disabledByConflict) {
    disabledByConflict = false;
    if (proxyConfig.host && Number(proxyConfig.port) > 0) {
      extensionEnabled = true;
      await browser.storage.local.set({ extensionEnabled: true, disabledByConflict: false });
      rebuildMaps();
      await syncToolbarIcon();
      await refreshActiveBadge();
    } else {
      await browser.storage.local.set({ disabledByConflict: false });
    }
  }
  return isBlocked;
}

function reply(sendResponse, task) {
  Promise.resolve(task)
    .then(res => sendResponse(res))
    .catch(e => sendResponse({ success: false, error: String((e && e.message) || e) }));
}

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  initPromise.then(() => {
    if (msg.action === "pingAllProxies") {
      reply(sendResponse, pingAllServers(msg.servers).then(results => ({ success: true, results })));
      return;
    }
    if (msg.action === "fetchList") {
      reply(sendResponse, enqueueListUpdate(() => fetchAndStoreList(msg.url, msg.id, msg)).then(() => ({ success: true })));
      return;
    }
    if (msg.action === "saveListMeta") {
      reply(sendResponse, enqueueListUpdate(() => saveListMeta(msg)).then(() => ({ success: true })));
      return;
    }
    if (msg.action === "setListEnabled") {
      reply(sendResponse, enqueueListUpdate(() => setListEnabled(msg.id, msg.enabled)).then(() => ({ success: true })));
      return;
    }
    if (msg.action === "deleteList") {
      reply(sendResponse, enqueueListUpdate(() => deleteList(msg.id)).then(() => ({ success: true })));
      return;
    }
    if (msg.action === "refreshList") {
      const list = proxyLists.find(x => x.id === msg.id);
      if (!list) { sendResponse({ success: false, error: "Список не найден" }); return; }
      reply(sendResponse, enqueueListUpdate(() => fetchAndStoreList(list.url, list.id, list)).then(() => ({ success: true })));
      return;
    }
    if (msg.action === "refreshLists") {
      reply(sendResponse, updateAllLists().then(res => ({ success: true, updated: res.updated, failed: res.failed })));
      return;
    }
    if (msg.action === "coverInfoMany") {
      sendResponse({ covers: HostRules.coverMany(msg.hosts, maps.compiledLists) });
      return;
    }
    if (msg.action === "coverInfo") {
      sendResponse(HostRules.coverPayload(msg.host || "", maps.compiledLists));
      return;
    }
    if (msg.action === "getTabDomains") {
      (async () => {
        if (!tabHosts[msg.tabId] && msg.tabId != null && msg.tabId >= 0) {
          try {
            const tab = await browser.tabs.get(msg.tabId);
            seedTabUrl(msg.tabId, tab && (tab.pendingUrl || tab.url));
          } catch (_) {}
        }
        const domains = tabHosts[msg.tabId] ? Array.from(tabHosts[msg.tabId]) : [];
        sendResponse({ domains: domains.filter(d => !HostRules.isIgnoredHost(d)).sort() });
      })().catch(() => sendResponse({ domains: [] }));
      return true;
    }
    if (msg.action === "checkProxyControl") {
      if (browser.proxy.settings && typeof browser.proxy.settings.get === "function") {
        browser.proxy.settings.get({}).then(async details => {
          const level = (details && details.levelOfControl) || "";
          sendResponse({ levelOfControl: level, isBlocked: await handleConflictControl(level) });
        }).catch(() => sendResponse({ levelOfControl: "", isBlocked: false }));
      } else {
        sendResponse({ levelOfControl: "", isBlocked: false });
      }
      return;
    }
    sendResponse({});
  }).catch(e => sendResponse({ success: false, error: String((e && e.message) || e) }));
  return true;
});

try {
  if (browser.proxy.settings && browser.proxy.settings.onChange) {
    browser.proxy.settings.onChange.addListener(details => {
      initPromise
        .then(() => handleConflictControl((details && details.levelOfControl) || ""))
        .catch(() => {});
    });
  }
} catch (_) {}

browser.alarms.onAlarm.addListener(alarm => {
  if (alarm.name !== "updateLists") return;
  initPromise.then(updateDueLists).finally(scheduleListUpdates);
});

async function handleStorageChanges(changes) {
  let need = false;
  if (changes.disabledByConflict) disabledByConflict = !!changes.disabledByConflict.newValue;
  if (changes.proxyServers) {
    proxyServers = Array.isArray(changes.proxyServers.newValue) ? changes.proxyServers.newValue : [];
    proxyConfig = ProxyConfig.configFromServers(ProxyConfig.migrateProxyServers(proxyServers, null));
    if (!proxyConfig.host && extensionEnabled) {
      extensionEnabled = false;
      browser.storage.local.set({ extensionEnabled: false });
    }
    need = true;
  } else if (changes.proxyConfig) {
    proxyConfig = changes.proxyConfig.newValue || proxyConfig;
    need = true;
  }
  if (changes.proxyRules) { proxyRules = changes.proxyRules.newValue || []; need = true; }
  if (changes.directRules) { directRules = changes.directRules.newValue || []; need = true; }
  if (changes.proxyLists) {
    proxyLists = changes.proxyLists.newValue || [];
    need = true;
    scheduleListUpdates();
  }
  if (changes.extensionEnabled) {
    extensionEnabled = !!changes.extensionEnabled.newValue && !!proxyConfig.host;
    need = true;
  }
  if (need) {
    rebuildMaps();
    await syncToolbarIcon();
    await refreshActiveBadge();
  }
}

browser.storage.onChanged.addListener(changes => {
  initPromise.then(() => handleStorageChanges(changes)).catch(() => {});
});

async function initBackground() {
  const res = await browser.storage.local.get(["proxyConfig", "proxyServers", "proxyRules", "directRules", "proxyLists", "extensionEnabled", "disabledByConflict"]);
  proxyServers = ProxyConfig.migrateProxyServers(res.proxyServers, res.proxyConfig);
  proxyConfig = ProxyConfig.configFromServers(proxyServers);
  extensionEnabled = (res.extensionEnabled == null ? !!proxyConfig.host : !!res.extensionEnabled) && !!proxyConfig.host;
  disabledByConflict = !!res.disabledByConflict;

  const persist = {};
  if (JSON.stringify(proxyServers) !== JSON.stringify(res.proxyServers || [])) {
    persist.proxyServers = proxyServers;
    persist.proxyConfig = proxyConfig;
  }
  if (res.extensionEnabled !== extensionEnabled) persist.extensionEnabled = extensionEnabled;
  if (res.proxyRules) proxyRules = res.proxyRules;
  if (res.directRules) directRules = res.directRules;
  const rawLists = Array.isArray(res.proxyLists) ? res.proxyLists : [];
  const stale = rawLists.some(ListUpdate.isStalePac);
  proxyLists = rawLists.map(list => ListUpdate.migrateList(Object.assign({}, list)));
  if (JSON.stringify(rawLists) !== JSON.stringify(proxyLists)) persist.proxyLists = proxyLists;
  if (Object.keys(persist).length) await browser.storage.local.set(persist);

  if (sessionAvailable()) {
    try {
      const s = await browser.storage.session.get(["tabHosts", "tabApex"]);
      if (s && s.tabHosts && typeof s.tabHosts === "object") {
        Object.keys(s.tabHosts).forEach(id => {
          const arr = s.tabHosts[id];
          if (Array.isArray(arr)) {
            tabHosts[Number(id)] = new Set(arr);
          }
        });
      }
      if (s && s.tabApex && typeof s.tabApex === "object") {
        Object.assign(tabApex, s.tabApex);
      }
    } catch (_) {}
  }

  applyMaps(HostRules.rebuildMaps(proxyRules, directRules, proxyLists));
  await syncToolbarIcon();
  await refreshActiveBadge();
  initialized = true;

  browser.tabs.query({}).then(tabs => {
    tabs.forEach(tab => seedTabUrl(tab.id, tab.url));
  }).catch(() => {});

  if (browser.proxy.settings && typeof browser.proxy.settings.get === "function") {
    browser.proxy.settings.get({}).then(async details => {
      await handleConflictControl((details && details.levelOfControl) || "");
    }).catch(() => {});
  }

  if (stale) await updateAllLists();
  else await updateDueLists();
  await scheduleListUpdates();
}

const initPromise = initBackground();
