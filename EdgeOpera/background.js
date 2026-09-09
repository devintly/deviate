importScripts("pac-parse.js");

let proxyConfig = { type: "socks", host: "127.0.0.1", port: 1080, username: "", password: "" };
let proxyRules = [];
let proxyLists = [];
let pE = {}, pS = {}, bE = {}, bS = {};
let pIp = {}, bIp = {}, pCidr = [], bCidr = [];
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
      id: Date.now(), url, type, format: "pac",
      domains: lists.domains, ips: lists.ips, cidrs: lists.cidrs,
      domainCount: lists.domainCount, ipCount: lists.ipCount, updatedAt: Date.now()
    };
  }
  const domains = parseList(text);
  if (isPacUrl(url) && domains.length === 0) {
    const preview = String(text || "").replace(/\s+/g, " ").trim().slice(0, 180);
    throw new Error(preview ? `Ответ не похож на PAC-файл: ${preview}` : "Пустой ответ вместо PAC-файла");
  }
  return { id: Date.now(), url, type, format: "txt", domains, ips: [], cidrs: [], domainCount: domains.length, ipCount: 0, updatedAt: Date.now() };
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
  (list.cidrs || []).forEach(c => {
    if (c && c.net) cidrs.push(c);
  });
}

function rebuildMaps() {
  pE = {}; pS = {}; bE = {}; bS = {};
  pIp = {}; bIp = {}; pCidr = []; bCidr = [];
  proxyRules.forEach(r => {
    r = normalizeRule(r);
    if (!r) return;
    if (r.startsWith("*.")) pS["." + r.slice(2)] = 1;
    else { pE[r] = 1; pS["." + r] = 1; }
  });
  proxyLists.forEach(list => {
    if (list.type === "block") addListTargets(list, bE, bS, bIp, bCidr);
    else addListTargets(list, pE, pS, pIp, pCidr);
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

function isProxiedHost(host) {
  return matchMaps(host, pE, pS) || PacParse.matchIpLiteral(host, pIp, pCidr);
}

function cidrsToPac(cidrs) {
  return (cidrs || []).map(c => {
    const bits = Number(c.bits || 0);
    if (!c.net || !bits) return null;
    const mask = bits >= 32 ? 0xFFFFFFFF : ((0xFFFFFFFF << (32 - bits)) >>> 0);
    return [PacParse.ipToInt(c.net), mask];
  }).filter(Boolean);
}

function buildCompactPac() {
  rebuildMaps();
  const userProxy = PacParse.userProxyToPac(proxyConfig);
  const pPacked = PacParse.packDomainList(Object.keys(pE));
  const bPacked = PacParse.packDomainList(Object.keys(bE));
  return `
    var pPacked = ${JSON.stringify(pPacked)};
    var bPacked = ${JSON.stringify(bPacked)};
    var pS = ${JSON.stringify(pS)};
    var bS = ${JSON.stringify(bS)};
    var pIp = ${JSON.stringify(pIp)};
    var bIp = ${JSON.stringify(bIp)};
    var pCidr = ${JSON.stringify(cidrsToPac(pCidr))};
    var bCidr = ${JSON.stringify(cidrsToPac(bCidr))};
    var userProxy = ${JSON.stringify(userProxy)};
    function matchSuffix(host, suffix) {
      var parts = host.split("."), current = "";
      for (var i = parts.length - 1; i >= 0; i--) {
        current = "." + parts[i] + current;
        if (suffix[current]) return true;
      }
      return false;
    }
    function matchPacked(host, packed) {
      if (!host || !packed) return false;
      host = String(host || "").toLowerCase().replace(/\\.$/, "").replace(/^www\\./, "");
      var variants = [host];
      var two = host.match(/([^.]+\\.[^.]+)$/);
      var three = host.match(/([^.]+\\.[^.]+\\.[^.]+)$/);
      if (two) variants.push(two[1]);
      if (three) variants.push(three[1]);
      for (var v = 0; v < variants.length; v++) {
        var s = variants[v];
        var dot = s.lastIndexOf(".");
        if (dot < 1) continue;
        var name = s.slice(0, dot), zone = s.slice(dot + 1);
        var byLen = packed[zone];
        if (!byLen) continue;
        var chunk = byLen[name.length];
        if (chunk == null) chunk = byLen[String(name.length)];
        if (typeof chunk !== "string") continue;
        var n = name.length;
        for (var p = 0; p + n <= chunk.length; p += n) {
          if (chunk.substr(p, n) === name) return true;
        }
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
        if (row && (n & row[1]) === (row[0] & row[1])) return true;
      }
      return false;
    }
    function isBlocked(host) {
      return matchPacked(host, bPacked) || matchSuffix(host, bS) || matchIp(host, bIp, bCidr);
    }
    function isProxied(host) {
      return matchPacked(host, pPacked) || matchSuffix(host, pS) || matchIp(host, pIp, pCidr);
    }
    function FindProxyForURL(url, host) {
      host = (host || "").toLowerCase();
      if (!host) return "DIRECT";
      if (isBlocked(host)) return "PROXY 127.0.0.1:9";
      if (isProxied(host)) return userProxy;
      if (!/^[0-9a-fA-F:.]*$/.test(host)) {
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
  const hasLocal = Object.keys(pE).length + Object.keys(pS).length + Object.keys(bE).length + Object.keys(bS).length > 0;
  const hasIp = Object.keys(pIp).length + Object.keys(bIp).length + pCidr.length + bCidr.length > 0;
  if (!hasLocal && !hasIp) {
    applyChromePac({ mode: "direct" });
    return;
  }
  applyChromePac({
    mode: "pac_script",
    pacScript: { data: buildCompactPac(), mandatory: false }
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

function updateBadge(tabId) {
  if (tabId == null || tabId < 0) return;
  const n = tabProxied[tabId] ? tabProxied[tabId].size : 0;
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#5865f2" });
  chrome.action.setBadgeText({ tabId, text: n ? String(n) : "" });
}

chrome.webRequest.onAuthRequired.addListener(
  function (details, callbackFn) {
    if (details.isProxy && proxyConfig.username && proxyConfig.password) {
      callbackFn({ authCredentials: { username: proxyConfig.username, password: proxyConfig.password } });
    } else callbackFn({});
  },
  { urls: ["<all_urls>"] },
  ["asyncBlocking"]
);

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;
    try {
      const host = new URL(details.url).hostname.toLowerCase();
      if (!host) return;
      rememberTabHost(details.tabId, host, isProxiedHost(host));
      updateBadge(details.tabId);
    } catch (e) {}
  },
  { urls: ["<all_urls>"] }
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

function fetchAndStoreList(url, type, existingId) {
  return fetch(url, {
    cache: "no-store",
    headers: { Accept: "application/x-ns-proxy-autoconfig, text/plain, application/javascript, */*" }
  })
    .then(async r => {
      const text = await r.text();
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${text.replace(/\s+/g, " ").trim().slice(0, 160)}`);
      const item = ingestRemote(url, type, text);
      delete item.pacScript;
      delete item.pacIndex;
      if (existingId != null) {
        item.id = existingId;
        const idx = proxyLists.findIndex(x => x.id === existingId);
        if (idx >= 0) proxyLists[idx] = Object.assign({}, proxyLists[idx], item, { url, type: proxyLists[idx].type || type });
        else proxyLists.push(item);
      } else proxyLists.push(item);
      return new Promise((resolve, reject) => {
        chrome.storage.local.set({ proxyLists, lastListUpdate: Date.now() }, () => {
          if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
          else resolve(item);
        });
      });
    });
}

async function updateAllLists() {
  if (!proxyLists.length) return { updated: 0 };
  let updated = 0;
  for (const list of proxyLists) {
    if (!list.url) continue;
    try { await fetchAndStoreList(list.url, list.type, list.id); updated++; } catch (e) {}
  }
  rebuildMaps();
  applyProxy();
  return { updated };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "fetchList") {
    fetchAndStoreList(msg.url, msg.type)
      .then(() => { applyProxy(); sendResponse({ success: true }); })
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
    sendResponse({ domains: domains.filter(d => !isProxiedHost(d)) });
    return true;
  }
});

chrome.alarms.create("updateLists", { periodInMinutes: 60 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "updateLists") updateAllLists();
});

chrome.storage.onChanged.addListener((changes) => {
  let need = false;
  if (changes.proxyConfig) { proxyConfig = changes.proxyConfig.newValue || proxyConfig; need = true; }
  if (changes.proxyRules) { proxyRules = changes.proxyRules.newValue || []; need = true; }
  if (changes.proxyLists) { proxyLists = changes.proxyLists.newValue || []; need = true; }
  if (need) applyProxy();
});

function isStalePac(list) {
  if (!list || list.format !== "pac" || !list.url) return false;
  if (list.pacScript || list.pacIndex) return true;
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

chrome.storage.local.get(["proxyConfig", "proxyRules", "proxyLists"], (res) => {
  if (res.proxyConfig) proxyConfig = res.proxyConfig;
  if (res.proxyRules) proxyRules = res.proxyRules;
  if (res.proxyLists) proxyLists = (res.proxyLists || []).map(stripLegacyPac);
  applyProxy();
  if (proxyLists.some(isStalePac)) updateAllLists();
});
