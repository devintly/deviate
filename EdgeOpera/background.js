let proxyConfig = { type: "socks", host: "127.0.0.1", port: 1080, username: "", password: "" };
let proxyRules = [];
let proxyLists = [];

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

function isPacList(list) {
  return list && (list.format === "pac" || (!!list.pacScript && isPacText(list.pacScript)));
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
      let domain = line.substring(2, endIdx).split("$")[0];
      if (domain) domains.add(domain);
      continue;
    }
    if (/^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i.test(line)) domains.add(line);
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

function init() {
  chrome.storage.local.get(["proxyConfig", "proxyRules", "proxyLists"], (res) => {
    if (res.proxyConfig) proxyConfig = res.proxyConfig;
    if (res.proxyRules) proxyRules = res.proxyRules;
    if (res.proxyLists) proxyLists = res.proxyLists;
    applyProxy();
  });
}

function buildCombinedPac() {
  let domains = [];
  proxyRules.forEach(r => {
    let d = String(r || "").replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
    if (d) domains.push(d);
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
    if (list.type === "proxy" && list.domains) {
      list.domains.forEach(d => { if (d) domains.push(d); });
    }
  });

  const proxyType = proxyConfig.type === "socks" ? "SOCKS5" : "PROXY";
  const proxyStr = `${proxyType} ${proxyConfig.host}:${proxyConfig.port}`;

  return `
    ${pacParts.join("\n")}
    function pacIsDirect(s) {
      var first = String(s == null ? "DIRECT" : s).split(";")[0].toUpperCase();
      return /^\\s*DIRECT\\s*$/.test(first) || /^\\s*$/.test(first);
    }
    function FindProxyForURL(url, host) {
      var domains = ${JSON.stringify(domains)};
      var p = "${proxyStr}; DIRECT";
      host = (host || "").toLowerCase();
      for (var i = 0; i < domains.length; i++) {
        var d = domains[i];
        if (d.indexOf("*.") === 0) {
           var suffix = d.substring(1);
           if (host === d.substring(2) || host.indexOf(suffix, host.length - suffix.length) !== -1) {
              return p;
           }
        } else {
           if (host === d || host.indexOf("." + d, host.length - ("." + d).length) !== -1) {
              return p;
           }
        }
      }
      ${pacCalls.join("\n      ")}
      return "DIRECT";
    }
  `;
}

function applyChromePac(value, done) {
  chrome.proxy.settings.set({ value, scope: "regular" }, () => {
    if (chrome.runtime.lastError) {
      const err = chrome.runtime.lastError.message;
      chrome.storage.local.set({ lastProxyError: err });
      if (done) done(err);
    } else {
      chrome.storage.local.set({ lastProxyError: "" });
      if (done) done("");
    }
  });
}

function applyProxy() {
  if (!proxyConfig.host) return;

  const directUrl = singleDirectPacUrl();
  if (directUrl) {
    applyChromePac({
      mode: "pac_script",
      pacScript: { url: directUrl, mandatory: false }
    });
    return;
  }

  const hasPac = proxyLists.some(l => isPacList(l) && l.pacScript);
  if (!hasPac && proxyRules.length === 0 && !hasTxtRouting()) {
    applyChromePac({ mode: "system" });
    return;
  }

  const pacCode = buildCombinedPac();
  applyChromePac({
    mode: "pac_script",
    pacScript: { data: pacCode, mandatory: false }
  }, (err) => {
    if (!err) return;
    const fallback = (proxyLists.filter(isPacList)[0] || {}).url;
    if (fallback && !hasTxtRouting()) {
      applyChromePac({
        mode: "pac_script",
        pacScript: { url: fallback, mandatory: false }
      });
    }
  });
}

chrome.webRequest.onAuthRequired.addListener(
  function(details, callbackFn) {
    if (details.isProxy && proxyConfig.username && proxyConfig.password) {
      callbackFn({
        authCredentials: { username: proxyConfig.username, password: proxyConfig.password }
      });
    } else {
      callbackFn({});
    }
  },
  {urls: ["<all_urls>"]},
  ["asyncBlocking"]
);

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
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
        return chrome.storage.local.set({ proxyLists });
      })
      .then(() => {
        applyProxy();
        sendResponse({ success: true });
      })
      .catch(e => sendResponse({ success: false, error: String(e.message || e) }));
    return true;
  }
});

chrome.storage.onChanged.addListener((changes) => {
  let update = false;
  if (changes.proxyConfig) { proxyConfig = changes.proxyConfig.newValue || proxyConfig; update = true; }
  if (changes.proxyRules) { proxyRules = changes.proxyRules.newValue || []; update = true; }
  if (changes.proxyLists) { proxyLists = changes.proxyLists.newValue || []; update = true; }
  if (update) applyProxy();
});

init();
