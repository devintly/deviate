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

function isHostProxied(host) {
  return HostRules.hostIsProxied(host, extensionEnabled, maps);
}

function recordTabHost(tabId, host) {
  const stored = HostRules.rememberHost(tabHosts, tabId, host);
  if (!stored) return;
  if (isHostProxied(stored)) {
    if (!tabProxied[tabId]) tabProxied[tabId] = new Set();
    tabProxied[tabId].add(stored);
    scheduleBadge(tabId);
  }
}

function recountTabProxied() {
  Object.keys(tabHosts).forEach(id => {
    const tabId = Number(id);
    const next = new Set();
    const hosts = tabHosts[tabId];
    if (hosts && extensionEnabled) {
      hosts.forEach(h => { if (isHostProxied(h)) next.add(h); });
    }
    tabProxied[tabId] = next;
    scheduleBadge(tabId);
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
    try { recordTabHost(details.tabId, new URL(details.url).hostname); } catch (_) {}
  },
  { urls: ["http://*/*", "https://*/*", "ws://*/*", "wss://*/*"] }
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && HostRules.isWebTab(tab, ownPageBase())) {
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

chrome.tabs.onActivated.addListener(info => scheduleBadge(info.tabId));

function scheduleBadge(tabId) {
  if (tabId == null || tabId < 0 || badgeWait[tabId]) return;
  badgeWait[tabId] = true;
  setTimeout(() => {
    delete badgeWait[tabId];
    flushBadge(tabId);
  }, 100);
}

async function flushBadge(tabId) {
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
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0]) scheduleBadge(tabs[0].id);
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

async function handleConflictControl(level) {
  const isBlocked = level === "controlled_by_other_extensions";
  if (isBlocked) {
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
  return isBlocked;
}

function reply(sendResponse, task) {
  Promise.resolve(task)
    .then(res => sendResponse(res))
    .catch(e => sendResponse({ success: false, error: String((e && e.message) || e) }));
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.target === "offscreen") return false;
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
      const set = tabHosts[msg.tabId];
      sendResponse({ domains: set ? Array.from(set).sort() : [] });
      return;
    }
    if (msg.action === "getProxyError") {
      sendResponse({ error: proxyApplyError });
      return;
    }
    if (msg.action === "checkProxyControl") {
      try {
        chrome.proxy.settings.get({ incognito: false }, details => {
          const error = chrome.runtime.lastError;
          if (error) {
            sendResponse({ levelOfControl: "", isBlocked: false, error: error.message || String(error) });
            return;
          }
          const level = (details && details.levelOfControl) || "";
          handleConflictControl(level)
            .then(isBlocked => sendResponse({ levelOfControl: level, isBlocked }))
            .catch(() => sendResponse({ levelOfControl: level, isBlocked: false }));
        });
      } catch (_) {
        sendResponse({ levelOfControl: "", isBlocked: false });
      }
      return;
    }
    sendResponse({});
  }).catch(e => sendResponse({ success: false, error: String((e && e.message) || e) }));
  return true;
});

try {
  if (chrome.proxy.settings.onChange) {
    chrome.proxy.settings.onChange.addListener(details => {
      ensureInit()
        .then(() => handleConflictControl((details && details.levelOfControl) || ""))
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

  rebuildMaps();
  recountTabProxied();
  try { await applyProxySettings(); } catch (_) {}

  try {
    chrome.proxy.settings.get({ incognito: false }, async details => {
      await handleConflictControl((details && details.levelOfControl) || "");
    });
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
