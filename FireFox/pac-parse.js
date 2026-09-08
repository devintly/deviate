(function (root) {
  "use strict";

  var THREE_PART = /^(ru|co|cu|com|info|net|org|gov|edu|int|mil|biz|pp|ne|msk|spb|nnov|od|in|ho|cc|dn|i|tut|v|dp|sl|ddns|dyndns|livejournal|herokuapp|azurewebsites|cloudfront|ucoz|3dn|nov|linode|sl-reverse|kiev|beget|kirov|akadns|scaleway|fastly|hldns|appspot|my1|hwcdn|deviantart|wixmp|wix|netdna-ssl|brightcove|berlogovo|edgecastcdn|trafficmanager|pximg|github|hopto|u-stream|google|keenetic|eu|googleusercontent|3nx|itch|notion|maryno|vercel|pythonanywhere|force|tilda|ggpht|iboards|mybb2|h1n|bdsmlr|narod|sb-cd)\.[^.]+$/;
  var DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
  var SKIP_WORDS = { function: 1, return: 1, direct: 1, proxy: 1, socks: 1, https: 1, http: 1, host: 1, url: 1 };

  function extractBalanced(text, start) {
    var depth = 0, inStr = false, quote = "", esc = false;
    for (var i = start; i < text.length; i++) {
      var c = text[i];
      if (inStr) {
        if (esc) { esc = false; continue; }
        if (c === "\\") { esc = true; continue; }
        if (c === quote) inStr = false;
        continue;
      }
      if (c === "\"" || c === "'") { inStr = true; quote = c; continue; }
      if (c === "{") depth++;
      else if (c === "}") {
        depth--;
        if (depth === 0) return text.slice(start, i + 1);
      }
    }
    return "";
  }

  function extractArray(text, start) {
    var depth = 0, inStr = false, quote = "", esc = false;
    for (var i = start; i < text.length; i++) {
      var c = text[i];
      if (inStr) {
        if (esc) { esc = false; continue; }
        if (c === "\\") { esc = true; continue; }
        if (c === quote) inStr = false;
        continue;
      }
      if (c === "\"" || c === "'") { inStr = true; quote = c; continue; }
      if (c === "[") depth++;
      else if (c === "]") {
        depth--;
        if (depth === 0) return text.slice(start, i + 1);
      }
    }
    return "";
  }

  function safeEval(expr) {
    try { return new Function("return (" + expr + ")")(); } catch (e) { return null; }
  }

  function findAssign(text, name) {
    var re = new RegExp("(?:var\\s+)?" + name + "\\s*=\\s*", "m");
    var m = re.exec(text);
    if (!m) return "";
    var i = m.index + m[0].length;
    while (i < text.length && /\s/.test(text[i])) i++;
    if (text[i] === "{") return extractBalanced(text, i);
    if (text[i] === "[") return extractArray(text, i);
    return "";
  }

  function addDomain(set, value) {
    var d = String(value || "").trim().toLowerCase().replace(/^\*\./, "").replace(/^\./, "").replace(/^www\./, "");
    if (!d || SKIP_WORDS[d] || !DOMAIN_RE.test(d)) return;
    set[d] = 1;
  }

  function extractQuotedDomains(text, out) {
    var re = /["']((?:[a-z0-9-]+\.)+[a-z]{2,63})["']/gi;
    var m;
    while ((m = re.exec(text))) addDomain(out, m[1]);
  }

  function extractCompressedDomains(text) {
    var raw = findAssign(text, "domains");
    if (!raw) return null;
    return safeEval(raw);
  }

  function extractPatterns(text) {
    var raw = findAssign(text, "patterns");
    if (raw) {
      var obj = safeEval(raw);
      if (obj) return obj;
    }
    var fn = text.match(/function\s+patternreplace\s*\([\s\S]*?var\s+patterns\s*=\s*(\{[\s\S]*?\})\s*;/);
    if (fn) return safeEval(fn[1]);
    return null;
  }

  function decodeIpList(text) {
    var raw = findAssign(text, "d_ipaddr");
    if (!raw) return [];
    var arr = safeEval(raw);
    if (!Array.isArray(arr) || !arr.length) return [];
    var out = [], prev = 0;
    for (var i = 0; i < arr.length; i++) {
      var n = parseInt(arr[i], 36);
      if (!isFinite(n)) continue;
      prev = n + prev;
      out.push(prev >>> 0);
    }
    return out;
  }

  function extractSpecial(text) {
    var raw = findAssign(text, "special");
    if (!raw) return [];
    var arr = safeEval(raw);
    return Array.isArray(arr) ? arr : [];
  }

  function extractPacProxies(text) {
    var found = [];
    var seen = {};
    var re = /return\s+["']([^"']+)["']/gi;
    var m;
    while ((m = re.exec(text))) {
      var parts = m[1].split(";");
      for (var i = 0; i < parts.length; i++) {
        var mm = String(parts[i] || "").trim().match(/^(HTTPS|PROXY|SOCKS5|SOCKS4|SOCKS)\s+([^:\s]+):(\d+)/i);
        if (!mm) continue;
        var key = mm[1].toUpperCase() + " " + mm[2] + ":" + mm[3];
        if (seen[key]) continue;
        seen[key] = 1;
        found.push({ type: mm[1].toUpperCase(), host: mm[2], port: Number(mm[3]) });
      }
    }
    return found;
  }

  function expandCompressed(domainsObj, limit) {
    var out = {};
    if (!domainsObj || typeof domainsObj !== "object") return out;
    var count = 0;
    limit = limit || 250000;
    var zones = Object.keys(domainsObj);
    for (var z = 0; z < zones.length; z++) {
      var zone = zones[z];
      var byLen = domainsObj[zone];
      if (!byLen || typeof byLen !== "object") continue;
      var lens = Object.keys(byLen);
      for (var l = 0; l < lens.length; l++) {
        var len = parseInt(lens[l], 10);
        var chunk = byLen[lens[l]];
        if (typeof chunk !== "string" || !len) continue;
        for (var i = 0; i + len <= chunk.length; i += len) {
          if (count >= limit) return out;
          addDomain(out, chunk.slice(i, i + len) + "." + zone);
          count++;
        }
      }
    }
    return out;
  }

  function applyPatterns(s, patterns) {
    if (!patterns || typeof patterns !== "object") return s;
    var keys = Object.keys(patterns);
    for (var i = 0; i < keys.length; i++) {
      var token = keys[i];
      var full = patterns[token];
      if (!full) continue;
      if (s.indexOf(full) !== -1) s = s.split(full).join(token);
    }
    return s;
  }

  function toPacShortHost(host, patterns) {
    host = String(host || "").toLowerCase();
    if (!host) return "";
    if (THREE_PART.test(host)) host = host.replace(/(.+)\.([^.]+\.[^.]+\.[^.]+$)/, "$2");
    else host = host.replace(/(.+)\.([^.]+\.[^.]+$)/, "$2");
    host = host.replace(/^www\./, "");
    return applyPatterns(host, patterns);
  }

  function matchCompressed(shortHost, domains) {
    if (!domains || !shortHost) return false;
    var i = shortHost.lastIndexOf(".");
    if (i < 1) return false;
    var curhost = shortHost.slice(0, i);
    var curzone = shortHost.slice(i + 1);
    var zone = domains[curzone];
    if (!zone) return false;
    var arr = zone[curhost.length];
    if (arr == null) arr = zone[String(curhost.length)];
    if (arr == null) return false;
    if (typeof arr === "string") {
      var len = curhost.length;
      for (var p = 0; p + len <= arr.length; p += len) {
        if (arr.substr(p, len) === curhost) return true;
      }
      return false;
    }
    if (Array.isArray(arr)) return arr.indexOf(curhost) !== -1;
    return false;
  }

  function ipToInt(ip) {
    var p = String(ip || "").split(".");
    if (p.length !== 4) return 0;
    return ((Number(p[0]) << 24) >>> 0) + (Number(p[1]) << 16) + (Number(p[2]) << 8) + Number(p[3]);
  }

  function matchIpLiteral(host, ipSet, special) {
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return false;
    var n = ipToInt(host);
    if (ipSet && ipSet[n]) return true;
    if (special && special.length) {
      for (var i = 0; i < special.length; i++) {
        var row = special[i];
        if (!row) continue;
        var net = typeof row[0] === "string" ? ipToInt(row[0]) : 0;
        var bits = Number(row[1] || 0);
        if (!bits) continue;
        var mask = bits >= 32 ? 0xFFFFFFFF : ((0xFFFFFFFF << (32 - bits)) >>> 0);
        if ((n & mask) === (net & mask)) return true;
      }
    }
    return false;
  }

  function parsePacAssets(text) {
    text = String(text || "").replace(/^\uFEFF/, "");
    var exact = {};
    extractQuotedDomains(text, exact);
    var compressed = extractCompressedDomains(text);
    if (compressed) {
      var expanded = expandCompressed(compressed, 4000);
      var keys = Object.keys(expanded);
      for (var i = 0; i < keys.length; i++) exact[keys[i]] = 1;
    }
    var ipNums = decodeIpList(text);
    var ipSet = {};
    for (var j = 0; j < ipNums.length; j++) ipSet[ipNums[j]] = 1;
    var ipv4 = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    for (var k = 0; k < ipv4.length; k++) {
      var ip = ipv4[k];
      var parts = ip.split(".");
      if (parts.some(function (x) { return Number(x) > 255; })) continue;
      if (ip.indexOf("0.") === 0 || ip.indexOf("127.") === 0) continue;
      ipSet[ipToInt(ip)] = 1;
    }
    var proxies = extractPacProxies(text);
    var exactList = Object.keys(exact);
    return {
      exact: exact,
      compressed: compressed || null,
      patterns: extractPatterns(text),
      ipSet: ipSet,
      special: extractSpecial(text),
      proxies: proxies,
      domainCount: exactList.length,
      ipCount: Object.keys(ipSet).length
    };
  }

  function hostMatchesIndex(host, index) {
    if (!index || !host) return false;
    host = String(host || "").toLowerCase().replace(/\.$/, "");
    if (!host) return false;
    if (index.exact && (index.exact[host] || index.exact[host.replace(/^www\./, "")])) return true;
    if (index.compressed && matchCompressed(toPacShortHost(host, index.patterns), index.compressed)) return true;
    if (matchIpLiteral(host, index.ipSet, index.special)) return true;
    if (index.exact) {
      var parts = host.split(".");
      var cur = "";
      for (var i = parts.length - 1; i >= 0; i--) {
        cur = parts[i] + (cur ? "." + cur : "");
        if (index.exact[cur]) return true;
      }
    }
    return false;
  }

  function proxiesToPacString(proxies, fallback) {
    var bits = [];
    (proxies || []).forEach(function (p) {
      bits.push(p.type + " " + p.host + ":" + p.port);
    });
    if (!bits.length && fallback) bits.push(fallback);
    if (bits.length && bits[bits.length - 1].indexOf("DIRECT") === -1) bits.push("DIRECT");
    return bits.join("; ") || "DIRECT";
  }

  function proxyToFirefox(p) {
    if (!p) return { type: "direct" };
    var t = String(p.type || "").toLowerCase();
    if (t === "https") return { type: "https", host: p.host, port: p.port };
    if (t === "proxy" || t === "http") return { type: "http", host: p.host, port: p.port };
    if (t === "socks4") return { type: "socks4", host: p.host, port: p.port };
    if (t === "socks" || t === "socks5") return { type: "socks", host: p.host, port: p.port, proxyDNS: true };
    return { type: "direct" };
  }

  function userProxyToFirefox(cfg) {
    if (!cfg || !cfg.host || !cfg.port) return { type: "direct" };
    var t = cfg.type === "socks" ? "socks" : (cfg.type === "https" ? "https" : "http");
    var out = { type: t, host: cfg.host, port: Number(cfg.port) };
    if (t === "socks") out.proxyDNS = true;
    return out;
  }

  function userProxyToPac(cfg) {
    if (!cfg || !cfg.host || !cfg.port) return "DIRECT";
    var t = cfg.type === "socks" ? "SOCKS5" : (cfg.type === "https" ? "HTTPS" : "PROXY");
    return t + " " + cfg.host + ":" + cfg.port + "; DIRECT";
  }

  var api = {
    parsePacAssets: parsePacAssets,
    hostMatchesIndex: hostMatchesIndex,
    proxiesToPacString: proxiesToPacString,
    proxyToFirefox: proxyToFirefox,
    userProxyToFirefox: userProxyToFirefox,
    userProxyToPac: userProxyToPac,
    addDomain: addDomain,
    DOMAIN_RE: DOMAIN_RE
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.PacParse = api;
})(typeof self !== "undefined" ? self : this);
