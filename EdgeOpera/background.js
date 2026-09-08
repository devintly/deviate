importScripts("pac-parse.js");

let proxyConfig = { type: "socks", host: "127.0.0.1", port: 1080, username: "", password: "" };
let proxyRules = [];
let proxyLists = [];
let pE = {}, pS = {}, bE = {}, bS = {};
const tabHosts = {};
const tabProxied = {};

function normalizeRule(rule) {
  return String(rule || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
}

function isPacUrl(url) {
  try { return /\.(pac|dat)$/i.test(new URL(url).pathname); }
  catch (e) { return /\.pac(\?|#|$)/i.test(String(url || "")); }
}

function isPacText(text) {
  return /function\s+FindProxyForURL\s*\(/i.test(String(text || ""));
}

function isPacList(list) {
  return list && (list.format === "pac" || !!list.pacIndex);
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
  if (isPacText(text)) {
    const pacIndex = PacParse.parsePacAssets(text);
    return {
      id: Date.now(), url, type, format: "pac",
      domains: Object.keys(pacIndex.exact || {}).slice(0, 50),
      ips: Object.keys(pacIndex.ipSet || {}).slice(0, 20),
      domainCount: pacIndex.domainCount, ipCount: pacIndex.ipCount,
      pacIndex, updatedAt: Date.now()
    };
  }
  const domains = parseList(text);
  if (isPacUrl(url) && domains.length === 0) {
    const preview = String(text || "").replace(/\s+/g, " ").trim().slice(0, 180);
    throw new Error(preview ? `Ответ не похож на PAC-файл: ${preview}` : "Пустой ответ вместо PAC-файла");
  }
  return { id: Date.now(), url, type, format: "txt", domains, ips: [], domainCount: domains.length, ipCount: 0, updatedAt: Date.now() };
}

function rebuildMaps() {
  pE = {}; pS = {}; bE = {}; bS = {};
  proxyRules.forEach(r => {
    r = normalizeRule(r);
    if (!r) return;
    if (r.startsWith("*.")) pS["." + r.slice(2)] = 1;
    else { pE[r] = 1; pS["." + r] = 1; }
  });
  proxyLists.forEach(list => {
    if (isPacList(list)) return;
    const tExact = list.type === "block" ? bE : pE;
    const tSuffix = list.type === "block" ? bS : pS;
    (list.domains || []).forEach(d => {
      d = normalizeRule(d);
      if (!d) return;
      if (d.startsWith("*.")) tSuffix["." + d.slice(2)] = 1;
      else { tExact[d] = 1; tSuffix["." + d] = 1; }
    });
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
  if (matchMaps(host, pE, pS)) return true;
  for (const list of proxyLists) {
    if (!isPacList(list) || !list.pacIndex || list.type === "block") continue;
    if (PacParse.hostMatchesIndex(host, list.pacIndex)) return true;
  }
  return false;
}

function buildCompactPac() {
  rebuildMaps();
  const userProxy = PacParse.userProxyToPac(proxyConfig);
  const pacLists = proxyLists.filter(l => isPacList(l) && l.pacIndex).map(l => ({
    type: l.type,
    exact: l.pacIndex.exact || {},
    compressed: l.pacIndex.compressed || null,
    patterns: l.pacIndex.patterns || null,
    ipSet: l.pacIndex.ipSet || {},
    special: l.pacIndex.special || [],
    proxy: PacParse.proxiesToPacString(l.pacIndex.proxies || [], userProxy)
  }));
  return `
    var pE = ${JSON.stringify(pE)};
    var pS = ${JSON.stringify(pS)};
    var bE = ${JSON.stringify(bE)};
    var bS = ${JSON.stringify(bS)};
    var pacLists = ${JSON.stringify(pacLists)};
    var userProxy = ${JSON.stringify(userProxy)};
    var THREE_PART = /^(ru|co|cu|com|info|net|org|gov|edu|int|mil|biz|pp|ne|msk|spb|nnov|od|in|ho|cc|dn|i|tut|v|dp|sl|ddns|dyndns|livejournal|herokuapp|azurewebsites|cloudfront|ucoz|3dn|nov|linode|sl-reverse|kiev|beget|kirov|akadns|scaleway|fastly|hldns|appspot|my1|hwcdn|deviantart|wixmp|wix|netdna-ssl|brightcove|berlogovo|edgecastcdn|trafficmanager|pximg|github|hopto|u-stream|google|keenetic|eu|googleusercontent|3nx|itch|notion|maryno|vercel|pythonanywhere|force|tilda|ggpht|iboards|mybb2|h1n|bdsmlr|narod|sb-cd)\\.[^.]+$/;
    function applyPatterns(s, patterns) {
      if (!patterns) return s;
      for (var k in patterns) {
        if (patterns[k] && s.indexOf(patterns[k]) !== -1) s = s.split(patterns[k]).join(k);
      }
      return s;
    }
    function shortHost(host, patterns) {
      host = (host || "").toLowerCase();
      if (THREE_PART.test(host)) host = host.replace(/(.+)\\.([^\\.]+\\.[^\\.]+\\.[^.]+$)/, "$2");
      else host = host.replace(/(.+)\\.([^\\.]+\\.[^.]+$)/, "$2");
      return applyPatterns(host.replace(/^www\\./, ""), patterns);
    }
    function matchCompressed(sh, domains) {
      if (!domains || !sh) return false;
      var i = sh.lastIndexOf(".");
      if (i < 1) return false;
      var curhost = sh.slice(0, i), curzone = sh.slice(i + 1), zone = domains[curzone];
      if (!zone) return false;
      var arr = zone[curhost.length];
      if (arr == null) return false;
      if (typeof arr === "string") {
        for (var p = 0; p + curhost.length <= arr.length; p += curhost.length) {
          if (arr.substr(p, curhost.length) === curhost) return true;
        }
        return false;
      }
      return arr.indexOf && arr.indexOf(curhost) !== -1;
    }
    function ipToInt(ip) {
      var p = ip.split(".");
      return ((Number(p[0]) << 24) >>> 0) + (Number(p[1]) << 16) + (Number(p[2]) << 8) + Number(p[3]);
    }
    function matchMaps(host, exact, suffix) {
      if (exact[host]) return true;
      var parts = host.split("."), current = "";
      for (var i = parts.length - 1; i >= 0; i--) {
        current = "." + parts[i] + current;
        if (suffix[current]) return true;
      }
      return false;
    }
    function matchIndex(host, idx) {
      if (idx.exact && (idx.exact[host] || idx.exact[host.replace(/^www\\./, "")])) return true;
      if (idx.compressed && matchCompressed(shortHost(host, idx.patterns), idx.compressed)) return true;
      if (/^\\d{1,3}(?:\\.\\d{1,3}){3}$/.test(host) && idx.ipSet && idx.ipSet[ipToInt(host)]) return true;
      if (idx.exact) {
        var parts = host.split("."), cur = "";
        for (var i = parts.length - 1; i >= 0; i--) {
          cur = parts[i] + (cur ? "." + cur : "");
          if (idx.exact[cur]) return true;
        }
      }
      return false;
    }
    function FindProxyForURL(url, host) {
      host = (host || "").toLowerCase();
      if (matchMaps(host, bE, bS)) return "PROXY 127.0.0.1:9";
      if (matchMaps(host, pE, pS)) return userProxy;
      for (var i = 0; i < pacLists.length; i++) {
        if (matchIndex(host, pacLists[i])) {
          if (pacLists[i].type === "block") return "PROXY 127.0.0.1:9";
          return pacLists[i].proxy || userProxy;
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
  const hasPac = proxyLists.some(l => isPacList(l) && l.pacIndex);
  const hasLocal = Object.keys(pE).length + Object.keys(pS).length + Object.keys(bE).length + Object.keys(bS).length > 0;
  if (!hasPac && !hasLocal) {
    applyChromePac({ mode: "direct" });
    return;
  }
  const pacCode = buildCompactPac();
  applyChromePac({
    mode: "pac_script",
    pacScript: { data: pacCode, mandatory: false }
  }, (err) => {
    if (!err) return;
    const fallback = (proxyLists.find(l => isPacList(l) && l.url) || {}).url;
    if (fallback && !hasLocal) {
      applyChromePac({ mode: "pac_script", pacScript: { url: fallback, mandatory: false } });
    }
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
  return fetch(url, { cache: "no-store" })
    .then(async r => {
      const text = await r.text();
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${text.replace(/\s+/g, " ").trim().slice(0, 160)}`);
      const item = ingestRemote(url, type, text);
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

chrome.storage.local.get(["proxyConfig", "proxyRules", "proxyLists"], (res) => {
  if (res.proxyConfig) proxyConfig = res.proxyConfig;
  if (res.proxyRules) proxyRules = res.proxyRules;
  if (res.proxyLists) proxyLists = res.proxyLists;
  applyProxy();
});
