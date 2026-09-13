"use strict";

importScripts("pac-parse.js", "list-update.js", "list-ingest.js", "host-rules.js", "proxy-config.js", "generate-pac.js");

let proxyConfig = ProxyConfig.emptyConfig();
let proxyServers = [];
let proxyRules = [];
let directRules = [];
let proxyLists = [];
let extensionEnabled = false;
let disabledByConflict = false;
let maps = HostRules.rebuildMaps([], [], []);

const tabHosts = {};
const tabProxied = {};
const tabApex = {};
const tabTargetUrl = {};
const badgeWait = {};
let badgeColorsReady = false;
let listUpdateQueue = Promise.resolve();
let proxyMutex = Promise.resolve();
let initPromise = null;
let offscreenCreatePromise = null;
let proxyApplyError = "";
let proxyApplyErrorCode = "";
let mapsRevision = 0;
let pacCache = { key: "", code: "" };

function applyMaps(next) {
  maps = next;
  mapsRevision++;
}

// Все записи в chrome.proxy.settings идут через эту очередь: окно временной
// маршрутизации загрузки списка удерживает её, чтобы маршрут не перезатёрли.
function withProxyLock(fn) {
  const task = proxyMutex.then(fn, fn);
  proxyMutex = task.then(() => {}, () => {});
  return task;
}

function rebuildMaps() {
  applyMaps(HostRules.rebuildMaps(proxyRules, directRules, proxyLists));
  recountTabProxied();
}

function ownPageBase() {
  try { return chrome.runtime.getURL(""); } catch (_) { return ""; }
}

function sessionAvailable() {
  try {
    return !!(chrome.storage && chrome.storage.session && typeof chrome.storage.session.get === "function");
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
      await chrome.storage.session.set({ tabHosts: obj, tabApex: apexObj });
    } catch (_) {}
  }, 300);
}

function isHostProxied(host) {
  return HostRules.hostIsProxied(host, extensionEnabled, maps);
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

function resetTabForSite(tabId, apex, url) {
  if (tabId == null || tabId < 0) return;
  tabHosts[tabId] = new Set();
  tabProxied[tabId] = new Set();
  delete badgeTextCache[tabId];
  if (apex) tabApex[tabId] = apex;
  else delete tabApex[tabId];
  if (url) {
    if (url.startsWith("http:") || url.startsWith("https:")) {
      tabTargetUrl[tabId] = url;
    }
    const host = getUrlHost(url);
    if (host && !HostRules.isIgnoredHost(host)) {
      recordTabHost(tabId, host);
    }
  }
  scheduleBadge(tabId);
  persistTabHostsSession();
}

function seedTabUrl(tabId, url) {
  if (tabId == null || tabId < 0 || !url || HostRules.isOwnPage(url, ownPageBase())) return;
  const host = getUrlHost(url);
  if (!host || HostRules.isIgnoredHost(host)) return;
  const apex = HostRules.apexDomain(host);
  if (!tabApex[tabId]) {
    tabApex[tabId] = apex;
  } else if (apex && tabApex[tabId] && apex !== tabApex[tabId]) {
    resetTabForSite(tabId, apex, url);
    return;
  }
  recordTabHost(tabId, host);
}

function recordTabHost(tabId, host) {
  if (tabId == null || tabId < 0 || !host || HostRules.isIgnoredHost(host)) return;
  const canon = HostRules.canonHost(host);
  if (!canon) return;
  const existingHosts = tabHosts[tabId];
  const alreadyKnown = existingHosts && existingHosts.has(canon);
  const stored = HostRules.rememberHost(tabHosts, tabId, canon);
  if (!stored) return;
  let changed = !alreadyKnown;
  if (isHostProxied(stored)) {
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

function recountTabProxiedForTab(tabId) {
  const next = new Set();
  const hosts = tabHosts[tabId];
  if (hosts && extensionEnabled) {
    hosts.forEach(h => { if (isHostProxied(h)) next.add(h); });
  }
  tabProxied[tabId] = next;
  scheduleBadge(tabId);
  return next;
}

function recountTabProxied() {
  Object.keys(tabHosts).forEach(id => {
    recountTabProxiedForTab(Number(id));
  });
}

function proxyCallbackError() {
  const error = chrome.runtime.lastError;
  if (!error) return null;
  return ListUpdate.codedError("error_proxy_apply", error.message);
}

function setProxyPac(data) {
  return new Promise((resolve, reject) => {
    chrome.proxy.settings.set({
      value: { mode: "pac_script", pacScript: { data, mandatory: false } },
      scope: "regular"
    }, () => {
      const error = proxyCallbackError();
      if (error) reject(error);
      else resolve();
    });
  });
}

function clearProxy() {
  return new Promise((resolve, reject) => {
    chrome.proxy.settings.clear({ scope: "regular" }, () => {
      const error = proxyCallbackError();
      if (error) reject(error);
      else resolve();
    });
  });
}

// PAC для больших списков занимает мегабайты, поэтому его текст кэшируется
// и пересобирается только при смене правил, списков или самого прокси.
function activePacCode() {
  const proxyString = ProxyConfig.pacProxyString(proxyConfig);
  const probes = ProxyConfig.buildProbeMap(proxyServers);
  const key = `${mapsRevision}|${proxyString}|${JSON.stringify(probes)}`;
  if (pacCache.key !== key) {
    pacCache = { key, code: GeneratePac.generatePacScript(proxyString, maps, probes) };
  }
  return pacCache.code;
}

async function applyProxyState() {
  try {
    if (!extensionEnabled || !proxyConfig.host || Number(proxyConfig.port) <= 0) await clearProxy();
    else await setProxyPac(activePacCode());
    if (proxyApplyError || proxyApplyErrorCode) {
      proxyApplyError = "";
      proxyApplyErrorCode = "";
      await chrome.storage.local.remove(["proxyApplyError", "proxyApplyErrorCode"]);
    }
  } catch (error) {
    proxyApplyError = String(error && error.message || "").slice(0, 180);
    proxyApplyErrorCode = (error && error.code) || "error_proxy_apply";
    await chrome.storage.local.set({ proxyApplyError, proxyApplyErrorCode });
    await syncToolbarIcon();
    refreshActiveBadge();
    throw error;
  }
  await syncToolbarIcon();
  refreshActiveBadge();
}

function applyProxySettings() {
  return withProxyLock(applyProxyState);
}

chrome.webRequest.onAuthRequired.addListener(
  (details, callbackFn) => {
    ensureInit().then(() => {
      if (!details.isProxy) {
        callbackFn({});
        return;
      }
      const ch = details.challenger || {};
      const srv = ProxyConfig.findAuthServer(proxyServers, proxyConfig, ch.host, ch.port);
      callbackFn(srv ? { authCredentials: { username: srv.username, password: srv.password } } : {});
    }).catch(() => callbackFn({}));
  },
  { urls: ["<all_urls>"] },
  ["asyncBlocking"]
);

chrome.webRequest.onBeforeRequest.addListener(
  details => {
    if (details.tabId == null || details.tabId < 0) return;
    try {
      if (details.type === "main_frame" && details.url && (details.url.startsWith("http:") || details.url.startsWith("https:"))) {
        tabTargetUrl[details.tabId] = details.url;
      }
      const host = new URL(details.url).hostname;
      if (!host || HostRules.isIgnoredHost(host)) return;
      ensureInit().then(() => {
        if (details.type === "main_frame") {
          const navApex = HostRules.apexDomain(host);
          if (navApex && tabApex[details.tabId] && navApex !== tabApex[details.tabId]) {
            resetTabForSite(details.tabId, navApex, details.url);
          } else if (!tabApex[details.tabId] && navApex) {
            tabApex[details.tabId] = navApex;
          }
        }
        recordTabHost(details.tabId, host);
      }).catch(() => {});
    } catch (_) {}
  },
  { urls: ["http://*/*", "https://*/*", "ws://*/*", "wss://*/*"] }
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  ensureInit().then(() => {
    const explicitUrl = (changeInfo && changeInfo.url) || (tab && tab.pendingUrl) || "";
    if (explicitUrl && (explicitUrl.startsWith("http:") || explicitUrl.startsWith("https:"))) {
      tabTargetUrl[tabId] = explicitUrl;
    } else if (changeInfo && changeInfo.status === "complete" && tab && tab.url && (tab.url.startsWith("http:") || tab.url.startsWith("https:"))) {
      tabTargetUrl[tabId] = tab.url;
    }
    if (explicitUrl) {
      const targetHost = getUrlHost(explicitUrl);
      const targetApex = targetHost ? HostRules.apexDomain(targetHost) : "";
      if (targetApex && tabApex[tabId] && targetApex !== tabApex[tabId]) {
        resetTabForSite(tabId, targetApex, explicitUrl);
        return;
      }
      if (changeInfo && changeInfo.status === "loading") {
        resetTabForSite(tabId, targetApex || tabApex[tabId] || "", explicitUrl);
        return;
      }
      seedTabUrl(tabId, explicitUrl);
      scheduleBadge(tabId);
      return;
    }

    const status = changeInfo && changeInfo.status;
    const tabUrl = (tab && tab.url) || "";
    const tabHost = getUrlHost(tabUrl);
    const tabApexVal = tabHost ? HostRules.apexDomain(tabHost) : "";

    if (status === "loading") {
      if (tabApexVal && tabApex[tabId] && tabApexVal !== tabApex[tabId]) {
        return;
      }
      if (tabUrl && tabHost) {
        seedTabUrl(tabId, tabUrl);
      }
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
  }).catch(() => {});
});

chrome.tabs.onRemoved.addListener(tabId => {
  delete tabHosts[tabId];
  delete tabProxied[tabId];
  delete tabApex[tabId];
  delete tabTargetUrl[tabId];
  if (badgeWait[tabId]) {
    clearTimeout(badgeWait[tabId]);
    delete badgeWait[tabId];
  }
  persistTabHostsSession();
});

chrome.tabs.onActivated.addListener(async info => {
  if (info.tabId == null || info.tabId < 0) return;
  await ensureInit();
  try {
    const tab = await chrome.tabs.get(info.tabId);
    if (tab && tab.url) seedTabUrl(info.tabId, tab.url);
  } catch (_) {}
  scheduleBadge(info.tabId);
});

function scheduleBadge(tabId) {
  if (tabId == null || tabId < 0) return;
  if (badgeWait[tabId]) clearTimeout(badgeWait[tabId]);
  badgeWait[tabId] = setTimeout(() => {
    delete badgeWait[tabId];
    flushBadge(tabId);
  }, 80);
}

async function flushBadge(tabId) {
  if (tabId == null || tabId < 0) return;
  await ensureInit();
  if (!tabHosts[tabId] || tabHosts[tabId].size === 0) {
    try {
      const tab = await chrome.tabs.get(tabId);
      if (tab && tab.url) seedTabUrl(tabId, tab.url);
    } catch (_) {}
  }
  if ((!tabProxied[tabId] || tabProxied[tabId].size === 0) && tabHosts[tabId] && tabHosts[tabId].size > 0) {
    recountTabProxiedForTab(tabId);
  }
  const count = (extensionEnabled && tabProxied[tabId]) ? tabProxied[tabId].size : 0;
  try {
    if (!badgeColorsReady) {
      await chrome.action.setBadgeBackgroundColor({ color: "#6d6f78" });
      try { await chrome.action.setBadgeTextColor({ color: "#ffffff" }); } catch (_) {}
      badgeColorsReady = true;
    }
    await chrome.action.setBadgeText({ tabId, text: ProxyConfig.badgeText(count) });
  } catch (_) {}
}

async function refreshActiveBadge() {
  try {
    let tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs || !tabs.length) tabs = await chrome.tabs.query({ active: true });
    if (tabs && tabs.length) {
      tabs.forEach(tab => { if (tab && tab.id != null) scheduleBadge(tab.id); });
    }
  } catch (_) {}
}

async function syncToolbarIcon() {
  try {
    await chrome.action.setIcon({ path: ProxyConfig.iconPaths(ProxyConfig.toolbarIconOn(extensionEnabled, proxyConfig)) });
  } catch (_) {}
}

async function persistLists() {
  await chrome.storage.local.set({ proxyLists });
}

async function ensureOffscreenDocument() {
  if (chrome.runtime.getContexts) {
    const contexts = await chrome.runtime.getContexts({
      contextTypes: ["OFFSCREEN_DOCUMENT"],
      documentUrls: [chrome.runtime.getURL("offscreen.html")]
    });
    if (contexts.length) return;
  }
  if (!offscreenCreatePromise) {
    offscreenCreatePromise = chrome.offscreen.createDocument({
      url: "offscreen.html",
      reasons: ["WORKERS"],
      justification: "Разбор больших списков без блокировки service worker"
    }).catch(() => {}).finally(() => { offscreenCreatePromise = null; });
  }
  await offscreenCreatePromise;
}

async function ingestList(url, text) {
  await ensureOffscreenDocument();
  const response = await chrome.runtime.sendMessage({ target: "offscreen", action: "ingestList", url, text });
  if (!response || !response.success) {
    throw ListUpdate.codedError((response && response.code) || "error_parse", response && response.error);
  }
  return response.item;
}

async function closeOffscreenDocument() {
  try { await chrome.offscreen.closeDocument(); } catch (_) {}
}

async function fetchListTask(url, existingId, message) {
  try { return await fetchAndStoreList(url, existingId, message); }
  finally { await closeOffscreenDocument(); }
}

async function withFetchRoute(url, viaProxy, fn) {
  if (viaProxy && (!proxyConfig.host || !(Number(proxyConfig.port) > 0))) {
    throw new Error("Сначала добавьте прокси");
  }
  if (!viaProxy && (!extensionEnabled || !proxyConfig.host)) return fn();
  const host = new URL(url).hostname.toLowerCase();
  const temporary = Object.assign({}, maps, {
    dE: Object.assign({}, maps.dE),
    viaProxyHosts: Object.assign({}, maps.viaProxyHosts)
  });
  if (viaProxy) {
    temporary.viaProxyHosts[host] = 1;
    delete temporary.dE[host];
  } else {
    delete temporary.viaProxyHosts[host];
    temporary.dE[host] = 1;
  }
  await setProxyPac(GeneratePac.generatePacScript(
    ProxyConfig.pacProxyString(proxyConfig),
    temporary,
    ProxyConfig.buildProbeMap(proxyServers)
  ));
  try {
    return await fn();
  } finally {
    await applyProxySettings();
  }
}

async function fetchAndStoreList(url, existingId, msg) {
  url = String(url || "").trim();
  if (!ListUpdate.validListUrl(url)) throw new Error("Введите корректный URL");
  if (ListUpdate.findListByUrl(proxyLists, url, existingId)) throw new Error("Список добавить нельзя, он уже существует");
  const existing = existingId != null ? proxyLists.find(x => x.id === existingId) : null;
  const meta = ListUpdate.listMeta(msg || {}, existing);
  try {
    const body = await withFetchRoute(url, meta.viaProxy, async () => {
      const r = await fetch(url, {
        cache: "no-store",
        headers: { Accept: "application/x-ns-proxy-autoconfig, text/plain, application/javascript, */*" },
        signal: AbortSignal.timeout(45000)
      });
      const text = await r.text();
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${text.replace(/\s+/g, " ").trim().slice(0, 160)}`);
      return text;
    });
    const item = await ingestList(url, body);
    const stored = ListUpdate.commitFetchedList(proxyLists, item, meta, url, existingId, Date.now());
    rebuildMaps();
    await persistLists();
    await applyProxySettings();
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
  await applyProxySettings();
}

async function setListEnabled(id, enabled) {
  const list = proxyLists.find(item => item.id === id);
  if (!list) throw new Error("Список не найден");
  list.enabled = !!enabled;
  await persistLists();
  rebuildMaps();
  await applyProxySettings();
  await scheduleListUpdates();
  if (list.enabled && list.url && ListUpdate.isDue(list, Date.now())) {
    try {
      await fetchListTask(list.url, list.id, list);
    } catch (_) {}
  }
}

async function deleteList(id) {
  const length = proxyLists.length;
  proxyLists = proxyLists.filter(item => item.id !== id);
  if (proxyLists.length === length) throw new Error("Список не найден");
  await persistLists();
  rebuildMaps();
  await applyProxySettings();
  await scheduleListUpdates();
}

async function updateListedLists(all) {
  let updated = 0, failed = 0;
  const ids = proxyLists.filter(list => list && list.url && list.enabled !== false && (all || ListUpdate.isDue(list, Date.now()))).map(list => list.id);
  try {
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
  } finally {
    await closeOffscreenDocument();
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
      await chrome.alarms.clear("updateLists");
      return;
    }
    const existing = await chrome.alarms.get("updateLists");
    if (existing && !existing.periodInMinutes && Math.abs(existing.scheduledTime - when) < 15000) return;
    await chrome.alarms.create("updateLists", { when });
  } catch (_) {}
}

chrome.alarms.onAlarm.addListener(async alarm => {
  if (alarm.name !== "updateLists") return;
  await ensureInit();
  await updateDueLists();
  await scheduleListUpdates();
});

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
  const wasDisabled = !extensionEnabled || !proxyConfig.host;
  if (wasDisabled) await setProxyPac(GeneratePac.generateProbePac(ProxyConfig.buildProbeMap(targets)));
  const results = {};
  try {
    (await Promise.all(targets.map(pingServer))).forEach(res => {
      if (res && res.id != null) results[res.id] = { success: res.success, latency: res.latency };
    });
  } finally {
    if (wasDisabled) {
      if (!extensionEnabled || !proxyConfig.host) await clearProxy();
      else await applyProxySettings();
    }
  }
  return results;
}

async function getProxyStatus() {
  let settings = null;
  try {
    settings = await chrome.proxy.settings.get({ incognito: false });
  } catch (_) {
    try {
      settings = await chrome.proxy.settings.get({});
    } catch (_) {}
  }
  if (!settings) {
    try {
      settings = await new Promise(resolve => {
        chrome.proxy.settings.get({ incognito: false }, s => {
          const err = chrome.runtime.lastError;
          resolve(err ? null : s);
        });
      });
    } catch (_) {}
  }
  if (!settings) {
    try {
      settings = await new Promise(resolve => {
        chrome.proxy.settings.get({}, s => {
          const err = chrome.runtime.lastError;
          resolve(err ? null : s);
        });
      });
    } catch (_) {}
  }

  const level = (settings && settings.levelOfControl) || "";
  const val = (settings && settings.value) || {};
  const mode = (val && val.mode) || "";

  let isBlocked = false;
  if (level === "controlled_by_other_extensions" || level === "not_controllable") {
    isBlocked = true;
  } else if (!extensionEnabled && mode && mode !== "system" && mode !== "direct") {
    isBlocked = true;
  } else if (extensionEnabled && level === "controllable_by_this_extension" && mode && mode !== "system" && mode !== "direct") {
    isBlocked = true;
  }

  return {
    isActive: extensionEnabled,
    levelOfControl: level,
    isBlocked,
    settings: settings || {}
  };
}

async function handleConflictControl(isBlocked) {
  const blocked = typeof isBlocked === "boolean" ? isBlocked : (isBlocked && isBlocked.isBlocked) || false;
  if (blocked) {
    if (extensionEnabled) {
      extensionEnabled = false;
      disabledByConflict = true;
      await chrome.storage.local.set({ extensionEnabled: false, disabledByConflict: true });
      syncToolbarIcon();
      refreshActiveBadge();
    }
  } else if (disabledByConflict) {
    disabledByConflict = false;
    if (proxyConfig.host && Number(proxyConfig.port) > 0) {
      extensionEnabled = true;
      await chrome.storage.local.set({ extensionEnabled: true, disabledByConflict: false });
      rebuildMaps();
      recountTabProxied();
      await applyProxySettings();
    } else {
      await chrome.storage.local.set({ disabledByConflict: false });
    }
  }
  return blocked;
}

function reply(sendResponse, task) {
  Promise.resolve(task)
    .then(res => sendResponse(res))
    .catch(e => sendResponse({ success: false, error: String((e && e.message) || e) }));
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.target === "offscreen") return false;
  if (msg && msg.action === "getTabTarget") {
    const url = tabTargetUrl[msg.tabId] || "";
    const host = getUrlHost(url);
    const apex = host ? HostRules.apexDomain(host) : (tabApex[msg.tabId] || "");
    sendResponse({ targetUrl: url, targetHost: host, targetApex: apex });
    return true;
  }
  if (msg && (msg.action === "getProxyStatus" || msg.action === "checkProxyControl")) {
    getProxyStatus().then(async status => {
      await handleConflictControl(status.isBlocked);
      sendResponse(status);
    }).catch(err => {
      sendResponse({ levelOfControl: "", isBlocked: false, error: String(err) });
    });
    return true;
  }
  ensureInit().then(() => {
    if (msg.action === "pingAllProxies") {
      reply(sendResponse, enqueueListUpdate(() => pingAllServers(msg.servers)).then(results => ({ success: true, results })));
      return;
    }
    if (msg.action === "fetchList") {
      reply(sendResponse, enqueueListUpdate(() => fetchListTask(msg.url, msg.id, msg)).then(() => ({ success: true })));
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
      reply(sendResponse, enqueueListUpdate(() => fetchListTask(list.url, list.id, list)).then(() => ({ success: true })));
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
        if ((!tabHosts[msg.tabId] || tabHosts[msg.tabId].size === 0) && msg.tabId != null && msg.tabId >= 0) {
          try {
            const tab = await chrome.tabs.get(msg.tabId);
            if (tab && tab.url) seedTabUrl(msg.tabId, tab.url);
          } catch (_) {}
        }
        const set = tabHosts[msg.tabId];
        sendResponse({ domains: set ? Array.from(set).filter(d => !HostRules.isIgnoredHost(d)).sort() : [] });
      })().catch(() => sendResponse({ domains: [] }));
      return;
    }
    if (msg.action === "getProxyError") {
      sendResponse({ error: proxyApplyError });
      return;
    }
    sendResponse({});
  }).catch(e => sendResponse({ success: false, error: String((e && e.message) || e) }));
  return true;
});

try {
  if (chrome.proxy.settings.onChange) {
    chrome.proxy.settings.onChange.addListener(() => {
      ensureInit()
        .then(() => getProxyStatus())
        .then(status => handleConflictControl(status.isBlocked))
        .catch(() => {});
    });
  }
} catch (_) {}

chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area !== "local") return;
  await ensureInit();
  let needRebuild = false;
  if (changes.disabledByConflict) disabledByConflict = !!changes.disabledByConflict.newValue;
  if (changes.proxyServers) {
    proxyServers = Array.isArray(changes.proxyServers.newValue) ? changes.proxyServers.newValue : [];
    proxyConfig = ProxyConfig.configFromServers(proxyServers);
    if (!proxyConfig.host && extensionEnabled) {
      extensionEnabled = false;
      chrome.storage.local.set({ extensionEnabled: false });
    }
    needRebuild = true;
  }
  if (changes.proxyConfig && !changes.proxyServers) {
    proxyConfig = Object.assign({}, proxyConfig, changes.proxyConfig.newValue || {});
    needRebuild = true;
  }
  if (changes.proxyRules) { proxyRules = Array.isArray(changes.proxyRules.newValue) ? changes.proxyRules.newValue : []; needRebuild = true; }
  if (changes.directRules) { directRules = Array.isArray(changes.directRules.newValue) ? changes.directRules.newValue : []; needRebuild = true; }
  if (changes.proxyLists) {
    proxyLists = Array.isArray(changes.proxyLists.newValue) ? changes.proxyLists.newValue : [];
    needRebuild = true;
    scheduleListUpdates();
  }
  if (changes.extensionEnabled) {
    extensionEnabled = !!changes.extensionEnabled.newValue && !!proxyConfig.host;
    needRebuild = true;
  }
  if (needRebuild) {
    rebuildMaps();
    recountTabProxied();
    try { await applyProxySettings(); } catch (_) {}
  }
});

async function initBackground() {
  const res = await chrome.storage.local.get(["proxyConfig", "proxyServers", "proxyRules", "directRules", "proxyLists", "extensionEnabled", "disabledByConflict", "proxyApplyError"]);
  proxyServers = ProxyConfig.migrateProxyServers(res.proxyServers, res.proxyConfig);
  proxyConfig = ProxyConfig.configFromServers(proxyServers);
  proxyRules = Array.isArray(res.proxyRules) ? res.proxyRules : [];
  directRules = Array.isArray(res.directRules) ? res.directRules : [];
  const rawLists = Array.isArray(res.proxyLists) ? res.proxyLists : [];
  const stale = rawLists.some(ListUpdate.isStalePac);
  proxyLists = rawLists.map(list => ListUpdate.migrateList(Object.assign({}, list)));
  extensionEnabled = (res.extensionEnabled === undefined ? !!proxyConfig.host : !!res.extensionEnabled) && !!proxyConfig.host;
  disabledByConflict = !!res.disabledByConflict;
  proxyApplyError = String(res.proxyApplyError || "");

  const persist = {};
  if (!res.proxyServers || !res.proxyServers.length) persist.proxyServers = proxyServers;
  if (res.extensionEnabled !== extensionEnabled) persist.extensionEnabled = extensionEnabled;
  if (JSON.stringify(rawLists) !== JSON.stringify(proxyLists)) persist.proxyLists = proxyLists;
  if (Object.keys(persist).length) await chrome.storage.local.set(persist);

  if (sessionAvailable()) {
    try {
      const s = await chrome.storage.session.get(["tabHosts", "tabApex"]);
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

  try {
    await chrome.action.setBadgeBackgroundColor({ color: "#6d6f78" });
    try { await chrome.action.setBadgeTextColor({ color: "#ffffff" }); } catch (_) {}
    badgeColorsReady = true;
  } catch (_) {}

  try {
    const tabs = await chrome.tabs.query({});
    if (tabs && tabs.length) {
      tabs.forEach(tab => {
        if (tab && tab.id != null && tab.url) {
          seedTabUrl(tab.id, tab.url);
        }
      });
    }
  } catch (_) {}

  rebuildMaps();
  recountTabProxied();
  try { await applyProxySettings(); } catch (_) {}

  try {
    const status = await getProxyStatus();
    await handleConflictControl(status.levelOfControl);
  } catch (_) {}

  if (stale) await updateAllLists();
  else await updateDueLists();
  await scheduleListUpdates();
}

function ensureInit() {
  if (!initPromise) initPromise = initBackground();
  return initPromise;
}

ensureInit();
