importScripts("pac-parse.js");

let proxyConfig = { type: "socks", host: "", port: 0, username: "", password: "" };
let proxyRules = [];
let proxyLists = [];
let extensionEnabled = false;
let pE = {}, pS = {}, bE = {}, bS = {};
let pIp = {}, bIp = {}, pCidr = [], bCidr = [];
let pPac = [], bPac = [];
const ALL_WEB_URLS = ["http://*/*", "https://*/*", "ws://*/*", "wss://*/*"];
const tabHosts = {};
const tabProxied = {};
const fetchProxyHosts = {};
const fetchDirectHosts = {};

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
      id: Date.now(), url, type, format: "pac",
      packed: lists.packed,
      patterns: lists.patterns,
      threePart: lists.threePart,
      extra: lists.extra,
      domains: lists.extra,
      ips: lists.ips, cidrs: lists.cidrs,
      domainCount: lists.domainCount, ipCount: lists.ipCount
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

function collectPacMeta(block) {
  return (block ? bPac : pPac).map(list => ({
    packed: list.packed,
    patterns: list.patterns || null,
    threePart: list.threePart || "",
    extra: list.extra || []
  }));
}

function cidrsToPac(cidrs) {
  const out = [];
  for (let i = 0; i < (cidrs || []).length; i += 2) out.push([cidrs[i], cidrs[i + 1]]);
  return out;
}

function buildCompactPac() {
  rebuildMaps();
  const userProxy = PacParse.userProxyToPac(proxyConfig);
  const pPacked = PacParse.packDomainList(Object.keys(pE));
  const bPacked = PacParse.packDomainList(Object.keys(bE));
  const pPacLists = collectPacMeta(false);
  const bPacLists = collectPacMeta(true);
  return `
    var pPacked = ${JSON.stringify(pPacked)};
    var bPacked = ${JSON.stringify(bPacked)};
    var pS = ${JSON.stringify(pS)};
    var bS = ${JSON.stringify(bS)};
    var pIp = ${JSON.stringify(pIp)};
    var bIp = ${JSON.stringify(bIp)};
    var pCidr = ${JSON.stringify(cidrsToPac(pCidr))};
    var bCidr = ${JSON.stringify(cidrsToPac(bCidr))};
    var pPacLists = ${JSON.stringify(pPacLists)};
    var bPacLists = ${JSON.stringify(bPacLists)};
    var fetchProxy = ${JSON.stringify(fetchProxyHosts)};
    var fetchDirect = ${JSON.stringify(fetchDirectHosts)};
    var userProxy = ${JSON.stringify(userProxy)};
    var hasIpLists = ${JSON.stringify(!!(Object.keys(pIp).length || Object.keys(bIp).length || pCidr.length || bCidr.length))};
    function indexPacked(packed) {
      var idx = {}, zones = Object.keys(packed || {});
      for (var z = 0; z < zones.length; z++) {
        var zone = zones[z], byLen = packed[zone], names = idx[zone] = {};
        var lens = Object.keys(byLen || {});
        for (var l = 0; l < lens.length; l++) {
          var n = +lens[l], chunk = byLen[lens[l]];
          if (!n || typeof chunk !== "string") continue;
          for (var p = 0; p + n <= chunk.length; p += n) names[chunk.substr(p, n)] = 1;
        }
      }
      return idx;
    }
    function prepareLists(arr) {
      for (var i = 0; i < (arr || []).length; i++) {
        var list = arr[i];
        list.idx = indexPacked(list.packed);
        list.packed = null;
        list.threeRe = list.threePart ? new RegExp("\\\\.(" + list.threePart + ")\\\\.[^.]+$") : null;
        list.patKeys = list.patterns ? Object.keys(list.patterns) : null;
      }
      return arr;
    }
    pPacLists = prepareLists(pPacLists);
    bPacLists = prepareLists(bPacLists);
    pPacked = indexPacked(pPacked);
    bPacked = indexPacked(bPacked);
    function matchSuffix(host, suffix) {
      var parts = host.split("."), current = "";
      for (var i = parts.length - 1; i >= 0; i--) {
        current = "." + parts[i] + current;
        if (suffix[current]) return true;
      }
      return false;
    }
    function matchPacked(host, idx) {
      if (!host || !idx) return false;
      host = String(host).toLowerCase();
      if (host.charAt(host.length - 1) === ".") host = host.slice(0, -1);
      if (host.indexOf("www.") === 0) host = host.slice(4);
      var variants = [host];
      var two = host.match(/([^.]+\\.[^.]+)$/);
      var three = host.match(/([^.]+\\.[^.]+\\.[^.]+)$/);
      if (two) variants.push(two[1]);
      if (three) variants.push(three[1]);
      for (var v = 0; v < variants.length; v++) {
        var s = variants[v];
        var dot = s.lastIndexOf(".");
        if (dot < 1) continue;
        var names = idx[s.slice(dot + 1)];
        if (names && names[s.slice(0, dot)]) return true;
      }
      return false;
    }
    function applyPatterns(s, patterns, keys) {
      if (!patterns) return s;
      keys = keys || Object.keys(patterns);
      for (var i = 0; i < keys.length; i++) {
        var token = keys[i];
        s = String(s).split(patterns[token]).join(token);
      }
      return s;
    }
    function toShortHost(host, threeRe) {
      if (host.charAt(host.length - 1) === ".") host = host.slice(0, -1);
      if (threeRe && threeRe.test(host)) host = host.replace(/(.+)\\.([^\\.]+\\.[^\\.]+\\.[^.]+$)/, "$2");
      else host = host.replace(/(.+)\\.([^\\.]+\\.[^.]+$)/, "$2");
      if (host.indexOf("www.") === 0) host = host.slice(4);
      return host;
    }
    function matchPacList(host, list) {
      if (!list || !host) return false;
      host = String(host).toLowerCase();
      var extra = list.extra || [];
      for (var i = 0; i < extra.length; i++) {
        var d = extra[i];
        if (host === d || host.length > d.length && host.slice(-(d.length + 1)) === "." + d) return true;
      }
      var shost = toShortHost(host, list.threeRe);
      var dot = shost.lastIndexOf(".");
      if (dot < 1) return false;
      var name = list.patterns ? applyPatterns(shost.slice(0, dot), list.patterns, list.patKeys) : shost.slice(0, dot);
      var names = list.idx && list.idx[shost.slice(dot + 1)];
      return !!(names && names[name]);
    }
    function matchPacArr(host, arr) {
      for (var i = 0; i < (arr || []).length; i++) {
        if (matchPacList(host, arr[i])) return true;
      }
      return false;
    }
    function ipToInt(ip) {
      var p = String(ip || "").split(".");
      if (p.length !== 4) return 0;
      return ((Number(p[0]) << 24) >>> 0) + (Number(p[1]) << 16) + (Number(p[2]) << 8) + Number(p[3]);
    }
    function matchIp(host, ipMap, cidrs) {
      if (!/^\\d{1,3}(?:\\.\\d{1,3}){3}$/.test(host)) return false;
      if (ipMap && ipMap[host]) return true;
      var n = ipToInt(host);
      for (var i = 0; i < (cidrs || []).length; i++) {
        var row = cidrs[i];
        if (row && (n & row[1]) === row[0]) return true;
      }
      return false;
    }
    function isBlocked(host) {
      return matchPacked(host, bPacked) || matchSuffix(host, bS) || matchIp(host, bIp, bCidr) || matchPacArr(host, bPacLists);
    }
    function isProxied(host) {
      return matchPacked(host, pPacked) || matchSuffix(host, pS) || matchIp(host, pIp, pCidr) || matchPacArr(host, pPacLists);
    }
    function FindProxyForURL(url, host) {
      host = (host || "").toLowerCase();
      if (!host) return "DIRECT";
      if (fetchDirect[host]) return "DIRECT";
      if (fetchProxy[host]) return userProxy;
      if (isBlocked(host)) return "PROXY 127.0.0.1:9";
      if (isProxied(host)) return userProxy;
      if (hasIpLists && !/^[0-9a-fA-F:.]*$/.test(host)) {
        var oip = dnsResolve(host);
        if (oip) {
          if (isBlocked(oip)) return "PROXY 127.0.0.1:9";
          if (isProxied(oip)) return userProxy;
        }
      }
      return "DIRECT";
    }
  `;
}

function applyChromePac(value, done) {
  chrome.proxy.settings.set({ value, scope: "regular" }, () => {
    const err = chrome.runtime.lastError && chrome.runtime.lastError.message;
    chrome.storage.local.set({ lastProxyError: err || "" });
    if (done) done(err || "");
  });
}

function applyProxy() {
  rebuildMaps();
  return new Promise(resolve => {
    const done = () => resolve();
    if (!extensionEnabled) {
      applyChromePac({ mode: "direct" }, done);
      return;
    }
    const hasLocal = Object.keys(pE).length + Object.keys(pS).length + Object.keys(bE).length + Object.keys(bS).length > 0;
    const hasIp = Object.keys(pIp).length + Object.keys(bIp).length + pCidr.length + bCidr.length > 0;
    const hasPac = pPac.length + bPac.length > 0;
    const hasFetch = Object.keys(fetchProxyHosts).length + Object.keys(fetchDirectHosts).length > 0;
    if (!hasLocal && !hasIp && !hasPac && !hasFetch) {
      applyChromePac({ mode: "direct" }, done);
      return;
    }
    applyChromePac({
      mode: "pac_script",
      pacScript: { data: buildCompactPac(), mandatory: false }
    }, done);
  });
}

function rememberTabHost(tabId, host, proxied) {
  if (tabId < 0 || !host) return;
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
  }, 80);
}

function updateBadge(tabId) {
  if (tabId == null || tabId < 0) return;
  const n = extensionEnabled && tabProxied[tabId] ? tabProxied[tabId].size : 0;
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#5865f2" });
  chrome.action.setBadgeText({ tabId, text: n ? String(n) : "" });
}

chrome.webRequest.onAuthRequired.addListener(
  function (details, callbackFn) {
    if (details.isProxy && proxyConfig.username && proxyConfig.password) {
      callbackFn({ authCredentials: { username: proxyConfig.username, password: proxyConfig.password } });
    } else callbackFn({});
  },
  { urls: ALL_WEB_URLS },
  ["asyncBlocking"]
);

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;
    try {
      const host = new URL(details.url).hostname.toLowerCase();
      if (!host) return;
      rememberTabHost(details.tabId, host, isProxiedHost(host) && !isBlockedHost(host));
      scheduleBadge(details.tabId);
    } catch (e) {}
  },
  { urls: ALL_WEB_URLS }
);

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabHosts[tabId];
  delete tabProxied[tabId];
});
chrome.tabs.onActivated.addListener((info) => updateBadge(info.tabId));
chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (change.status === "loading" && change.url) {
    tabHosts[tabId] = new Set();
    tabProxied[tabId] = new Set();
  }
  updateBadge(tabId);
});

function withFetchRoute(url, viaProxy, fn) {
  let host = "";
  try { host = new URL(url).hostname.toLowerCase(); } catch (e) {}
  const bucket = viaProxy ? fetchProxyHosts : fetchDirectHosts;
  if (host) bucket[host] = (bucket[host] || 0) + 1;
  return applyProxy()
    .then(fn)
    .finally(() => {
      if (host) {
        bucket[host]--;
        if (bucket[host] <= 0) delete bucket[host];
      }
      return applyProxy();
    });
}

function fetchAndStoreList(url, type, existingId, msg) {
  url = String(url || "").trim();
  if (!url.startsWith("http")) return Promise.reject(new Error("Введите корректный URL"));
  if (findListByUrl(url, existingId)) return Promise.reject(new Error("Список добавить нельзя, он уже существует"));
  const existing = existingId != null ? proxyLists.find(x => x.id === existingId) : null;
  const meta = listMeta(msg || {}, existing);
  return withFetchRoute(url, meta.viaProxy, () => fetch(url, {
    cache: "no-store",
    headers: { Accept: "application/x-ns-proxy-autoconfig, text/plain, application/javascript, */*" },
    signal: AbortSignal.timeout ? AbortSignal.timeout(45000) : undefined
  }).then(async r => {
    const text = await r.text();
    if (!r.ok) throw new Error(`HTTP ${r.status}: ${text.replace(/\s+/g, " ").trim().slice(0, 160)}`);
    const item = ingestRemote(url, type || (existing && existing.type) || "proxy", text);
    delete item.pacScript;
    delete item.pacIndex;
    item.name = meta.name;
    item.intervalHours = meta.intervalHours;
    item.viaProxy = meta.viaProxy;
    item.updatedAt = Date.now();
    if (existingId != null) {
      item.id = existingId;
      const idx = proxyLists.findIndex(x => x.id === existingId);
      if (idx >= 0) proxyLists[idx] = Object.assign({}, proxyLists[idx], item, { url, type: type || proxyLists[idx].type || "proxy" });
      else proxyLists.push(item);
    } else proxyLists.push(item);
    return new Promise((resolve, reject) => {
      chrome.storage.local.set({ proxyLists }, () => {
        if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
        else resolve(item);
      });
    });
  }));
}

function saveListMeta(msg) {
  const idx = proxyLists.findIndex(x => x.id === msg.id);
  if (idx < 0) return Promise.reject(new Error("Список не найден"));
  const url = String(msg.url || proxyLists[idx].url || "").trim();
  if (!url.startsWith("http")) return Promise.reject(new Error("Введите корректный URL"));
  if (findListByUrl(url, msg.id)) return Promise.reject(new Error("Список добавить нельзя, он уже существует"));
  const meta = listMeta(msg, proxyLists[idx]);
  proxyLists[idx].name = meta.name;
  proxyLists[idx].intervalHours = meta.intervalHours;
  proxyLists[idx].viaProxy = meta.viaProxy;
  proxyLists[idx].type = msg.type || proxyLists[idx].type;
  proxyLists[idx].url = url;
  return new Promise((resolve, reject) => {
    chrome.storage.local.set({ proxyLists }, () => {
      if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
      else resolve();
    });
  });
}

async function updateAllLists() {
  if (!proxyLists.length) return { updated: 0 };
  let updated = 0;
  for (const list of proxyLists) {
    if (!list.url) continue;
    try { await fetchAndStoreList(list.url, list.type, list.id, list); updated++; } catch (e) {}
  }
  await applyProxy();
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
    try { await fetchAndStoreList(list.url, list.type, list.id, list); updated++; } catch (e) {}
  }
  if (updated) await applyProxy();
  return { updated };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
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

chrome.alarms.create("updateLists", { periodInMinutes: 30 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "updateLists") updateDueLists();
});

chrome.storage.onChanged.addListener((changes) => {
  let need = false;
  if (changes.proxyServers) {
    proxyConfig = configFromServers(migrateProxyServers(changes.proxyServers.newValue || [], null));
    need = true;
  } else if (changes.proxyConfig) {
    proxyConfig = changes.proxyConfig.newValue || proxyConfig;
    need = true;
  }
  if (changes.proxyRules) { proxyRules = changes.proxyRules.newValue || []; need = true; }
  if (changes.proxyLists) { proxyLists = changes.proxyLists.newValue || []; need = true; }
  if (changes.extensionEnabled) {
    extensionEnabled = !!changes.extensionEnabled.newValue && !!(proxyConfig && proxyConfig.host);
    need = true;
  }
  if (need) applyProxy();
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

chrome.storage.local.get(["proxyConfig", "proxyServers", "proxyRules", "proxyLists", "extensionEnabled"], (res) => {
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
  const finish = () => {
    if (res.proxyRules) proxyRules = res.proxyRules;
    if (res.proxyLists) proxyLists = (res.proxyLists || []).map(stripLegacyPac);
    applyProxy();
    if (proxyLists.some(isStalePac)) updateAllLists();
  };
  if (Object.keys(persist).length) chrome.storage.local.set(persist, finish);
  else finish();
});
