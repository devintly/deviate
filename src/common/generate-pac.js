(function (root) {
  "use strict";

  function serializePacLists(pacLists) {
    return (pacLists || []).map(function (p) {
      return {
        extra: p.extraMap || {},
        packed: p.packed || null,
        patterns: p.patterns || null,
        patKeys: p.patKeys || null,
        threePart: p.threePart || ""
      };
    });
  }

  function generatePacScript(proxyStr, maps, probeMap) {
    maps = maps || {};
    return `var PROXY = ${JSON.stringify(proxyStr)};
var dE = ${JSON.stringify(maps.dE || {})};
var dS = ${JSON.stringify(maps.dS || {})};
var dIp = ${JSON.stringify(maps.dIp || {})};
var pE = ${JSON.stringify(maps.pE || {})};
var pS = ${JSON.stringify(maps.pS || {})};
var pIp = ${JSON.stringify(maps.pIp || {})};
var pCidr = ${JSON.stringify(maps.pCidr || [])};
var hasIpRules = Object.keys(dIp).length || Object.keys(pIp).length || pCidr.length;
var viaProxy = ${JSON.stringify(maps.viaProxyHosts || {})};
var rawPac = ${JSON.stringify(serializePacLists(maps.pPac))};
var probeProxies = ${JSON.stringify(probeMap || {})};

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
      for (var p = 0; p + len <= chunk.length; p += len) names[chunk.substr(p, len)] = 1;
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
    extraList: p.extra ? Object.keys(p.extra) : [],
    patterns: p.patterns,
    patKeys: p.patKeys,
    threeRe: threeRe,
    idx: indexPacked(p.packed)
  };
});

function matchMaps(host, exact, suffix) {
  if (exact[host]) return true;
  var parts = host.split(".");
  var current = "";
  for (var i = parts.length - 1; i >= 0; i--) {
    current = "." + parts[i] + current;
    if (suffix[current]) return true;
  }
  return false;
}

function ipToInt(ip) {
  var p = (ip || "").split(".");
  if (p.length !== 4) return 0;
  return ((Number(p[0]) << 24) >>> 0) + (Number(p[1]) << 16) + (Number(p[2]) << 8) + Number(p[3]);
}

function matchCidrs(ipInt, cidrs) {
  for (var i = 0; i < cidrs.length; i += 2) {
    if ((ipInt & cidrs[i + 1]) === cidrs[i]) return true;
  }
  return false;
}

function applyPatterns(s, patterns, keys) {
  if (!patterns) return s;
  keys = keys || [];
  for (var i = 0; i < keys.length; i++) {
    var token = keys[i];
    s = String(s).split(patterns[token]).join(token);
  }
  return s;
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
  if (p.extraList) {
    for (var e = 0; e < p.extraList.length; e++) {
      var d = p.extraList[e];
      if (d && host.length > d.length && host.charCodeAt(host.length - d.length - 1) === 46 && host.indexOf(d, host.length - d.length) === host.length - d.length) return true;
    }
  }
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
  if (host.charAt(0) === "[" && host.charAt(host.length - 1) === "]") host = host.slice(1, -1);
  if (host.charCodeAt(host.length - 1) === 46) host = host.slice(0, -1);
  if (host.charCodeAt(0) === 46) host = host.slice(1);

  if (host === "cp.cloudflare.com") {
    var probeIdx = url.indexOf("__deviate_probe=");
    if (probeIdx !== -1) {
      var probeId = url.substring(probeIdx + 16).split("&")[0];
      if (probeProxies[probeId]) return probeProxies[probeId];
    }
  }

  if (viaProxy[host]) return PROXY;
  if (matchMaps(host, dE, dS) || dIp[host]) return "DIRECT";
  if (matchMaps(host, pE, pS) || pIp[host]) return PROXY;

  if (pCidr && pCidr.length && /^(?:\\d{1,3}\\.){3}\\d{1,3}$/.test(host)) {
    if (matchCidrs(ipToInt(host), pCidr)) return PROXY;
  }

  if (pacLists && pacLists.length) {
    for (var i = 0; i < pacLists.length; i++) {
      if (matchPac(host, pacLists[i])) return PROXY;
    }
  }

  if (hasIpRules && !/^(?:\\d{1,3}\\.){3}\\d{1,3}$/.test(host) && typeof dnsResolve === "function") {
    try {
      var resolved = dnsResolve(host);
      if (resolved) {
        if (dIp[resolved]) return "DIRECT";
        if (pIp[resolved] || (pCidr && pCidr.length && matchCidrs(ipToInt(resolved), pCidr))) return PROXY;
      }
    } catch (e) {}
  }

  return "DIRECT";
}`;
  }

  function generateProbePac(probeMap) {
    return `var probeProxies = ${JSON.stringify(probeMap || {})};
function FindProxyForURL(url, host) {
  if (host === "cp.cloudflare.com") {
    var probeIdx = url.indexOf("__deviate_probe=");
    if (probeIdx !== -1) {
      var probeId = url.substring(probeIdx + 16).split("&")[0];
      if (probeProxies[probeId]) return probeProxies[probeId];
    }
  }
  return "DIRECT";
}`;
  }

  var api = { generatePacScript: generatePacScript, generateProbePac: generateProbePac };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.GeneratePac = api;
})(typeof self !== "undefined" ? self : this);
