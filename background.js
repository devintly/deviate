let proxyConfig = { type: "socks", host: "127.0.0.1", port: 1080 };
let proxyRules = [];
let proxyLists = [];

function normalizeRule(rule) {
  return String(rule || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
}

function isPacUrl(url) {
  try {
    return /\.(pac|dat)$/i.test(new URL(url).pathname);
  } catch (e) {
    return /\.pac(\?|#|$)/i.test(String(url || ""));
  }
}

function isPacText(text) {
  return /function\s+FindProxyForURL\s*\(/i.test(String(text || ""));
}

function parseList(text) {
  const domains = new Set();
  const lines = text.split('\n');
  for (let line of lines) {
    line = line.trim().toLowerCase();
    if (!line || line.startsWith('!') || line.startsWith('#')) continue;

    const matchHosts = line.match(/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s]+)/);
    if (matchHosts) {
      domains.add(matchHosts[1]);
      continue;
    }

    if (line.startsWith('||')) {
      let endIdx = line.indexOf('^');
      if (endIdx === -1) endIdx = line.indexOf('/');
      if (endIdx === -1) endIdx = line.indexOf(':');
      if (endIdx === -1) endIdx = line.length;
      let domain = line.substring(2, endIdx).split('$')[0];
      if (domain) domains.add(domain);
      continue;
    }

    if (/^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i.test(line)) {
      domains.add(line);
    }
  }
  return Array.from(domains);
}

function parseRemoteList(url, text) {
  if (isPacText(text)) {
    return { format: "pac", domains: [], pacScript: String(text).replace(/^\uFEFF/, "") };
  }
  const domains = parseList(text);
  if (isPacUrl(url) && domains.length === 0) {
    const preview = String(text || "").replace(/\s+/g, " ").trim().slice(0, 180);
    throw new Error(preview ? `Ответ не похож на PAC-файл: ${preview}` : "Пустой ответ вместо PAC-файла");
  }
  return { format: "txt", domains, pacScript: "" };
}

function wrapRemotePac(pacSource, fnName) {
  return (
    "var " + fnName + " = (function() {\n" +
    String(pacSource || "") +
    "\n  return (typeof FindProxyForURL === 'function') ? FindProxyForURL : function(u, h) { return 'DIRECT'; };\n" +
    "})();\n"
  );
}

function pacFnName(list) {
  return "FindProxyForURL_pac" + String(list.id).replace(/\D/g, "");
}

function isPacList(list) {
  return list && (list.format === "pac" || (!!list.pacScript && isPacText(list.pacScript)));
}

function hasTxtRouting() {
  if (proxyRules.length) return true;
  return proxyLists.some(list => !isPacList(list) && Array.isArray(list.domains) && list.domains.length > 0);
}

function singleDirectPacUrl() {
  const pacs = proxyLists.filter(isPacList);
  if (pacs.length !== 1) return "";
  if (pacs[0].type === "block") return "";
  if (hasTxtRouting()) return "";
  return pacs[0].url || "";
}

function buildPacScript() {
  const pExact = {}; const pSuffix = {};
  const bExact = {}; const bSuffix = {};

  proxyRules.forEach(r => {
    r = normalizeRule(r);
    if (r.startsWith("*.")) pSuffix["." + r.slice(2)] = 1;
    else pExact[r] = 1;
  });

  const pacParts = [];
  const pacCalls = [];

  proxyLists.forEach(list => {
    if (isPacList(list)) {
      if (!list.pacScript) return;
      const fn = pacFnName(list);
      pacParts.push(wrapRemotePac(list.pacScript, fn));
      if (list.type === "block") {
        pacCalls.push(`if (typeof ${fn} === "function") { var _r = ${fn}(url, host); if (!pacIsDirect(_r)) return "PROXY 0.0.0.0:0"; }`);
      } else {
        pacCalls.push(`if (typeof ${fn} === "function") { var _r = ${fn}(url, host); if (!pacIsDirect(_r)) return _r; }`);
      }
      return;
    }
    const tExact = list.type === "block" ? bExact : pExact;
    const tSuffix = list.type === "block" ? bSuffix : pSuffix;
    (list.domains || []).forEach(d => {
      if (d.startsWith("*.")) {
        tSuffix["." + d.slice(2)] = 1;
      } else {
        tExact[d] = 1;
        tSuffix["." + d] = 1;
      }
    });
  });

  const proxyStr = `${proxyConfig.type === "socks" ? "SOCKS5" : "PROXY"} ${proxyConfig.host}:${proxyConfig.port}`;

  return `
    ${pacParts.join("\n")}
    var pE = ${JSON.stringify(pExact)};
    var pS = ${JSON.stringify(pSuffix)};
    var bE = ${JSON.stringify(bExact)};
    var bS = ${JSON.stringify(bSuffix)};
    function pacIsDirect(s) {
      var first = String(s == null ? "DIRECT" : s).split(";")[0].toUpperCase();
      return /^\\s*DIRECT\\s*$/.test(first) || /^\\s*$/.test(first);
    }
    function FindProxyForURL(url, host) {
      host = (host || "").toLowerCase();
      if (bE[host]) return "PROXY 0.0.0.0:0";
      var parts = host.split('.');
      var current = "";
      for (var i = parts.length - 1; i >= 0; i--) {
        current = "." + parts[i] + current;
        if (bS[current]) return "PROXY 0.0.0.0:0";
      }
      if (pE[host]) return "${proxyStr}; DIRECT";
      current = "";
      for (var i = parts.length - 1; i >= 0; i--) {
        current = "." + parts[i] + current;
        if (pS[current]) return "${proxyStr}; DIRECT";
      }
      ${pacCalls.join("\n      ")}
      return "DIRECT";
    }
  `;
}

async function setAutoConfigUrl(url) {
  await browser.proxy.settings.set({
    value: {
      proxyType: "autoConfig",
      autoConfigUrl: url
    }
  });
}

async function applyProxy() {
  try {
    const directUrl = singleDirectPacUrl();
    if (directUrl) {
      await setAutoConfigUrl(directUrl);
    } else {
      const pac = buildPacScript();
      try {
        await setAutoConfigUrl(`data:application/x-ns-proxy-autoconfig;charset=utf-8,${encodeURIComponent(pac)}`);
      } catch (e) {
        const fallback = (proxyLists.filter(isPacList)[0] || {}).url;
        if (fallback && !hasTxtRouting()) await setAutoConfigUrl(fallback);
        else throw e;
      }
    }
    await browser.storage.local.set({ lastProxyError: "" });
  } catch (e) {
    await browser.storage.local.set({ lastProxyError: String(e.message || e) });
  }
}

browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "fetchList") {
    fetch(msg.url, { cache: "no-store" })
      .then(async r => {
        const text = await r.text();
        if (!r.ok) throw new Error(`HTTP ${r.status}: ${text.replace(/\s+/g, " ").trim().slice(0, 160)}`);
        return text;
      })
      .then(text => {
        const parsed = parseRemoteList(msg.url, text);
        proxyLists.push({ id: Date.now(), url: msg.url, type: msg.type, ...parsed });
        return browser.storage.local.set({ proxyLists });
      })
      .then(applyProxy)
      .then(() => sendResponse({ success: true }))
      .catch(e => sendResponse({ success: false, error: String(e.message || e) }));
    return true;
  }
});

browser.storage.onChanged.addListener(async (changes) => {
  if (changes.proxyConfig) proxyConfig = changes.proxyConfig.newValue || proxyConfig;
  if (changes.proxyRules) proxyRules = changes.proxyRules.newValue || [];
  if (changes.proxyLists) proxyLists = changes.proxyLists.newValue || [];
  await applyProxy();
});

browser.storage.local.get(["proxyConfig", "proxyRules", "proxyLists"]).then(res => {
  if (res.proxyConfig) proxyConfig = res.proxyConfig;
  if (res.proxyRules) proxyRules = res.proxyRules;
  if (res.proxyLists) proxyLists = res.proxyLists;
  applyProxy();
});
