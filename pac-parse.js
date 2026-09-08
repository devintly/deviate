(function (root) {
  "use strict";

  var DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
  var SKIP_WORDS = { function: 1, return: 1, direct: 1, proxy: 1, socks: 1, https: 1, http: 1, host: 1, url: 1 };
  var IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

  function isHtmlDocument(text) {
    var t = String(text || "").replace(/^\uFEFF/, "").trim();
    if (!t) return false;
    if (/^<!DOCTYPE\s+html/i.test(t) || /^<html[\s>]/i.test(t)) return true;
    return /IPFS Service Worker Gateway/i.test(t) && /<html[\s>]/i.test(t);
  }

  function isPacText(text) {
    return /function\s+FindProxyForURL\s*\(/i.test(String(text || ""));
  }

  function addDomain(set, value) {
    var d = String(value || "").trim().toLowerCase().replace(/^\*\./, "").replace(/^\./, "").replace(/^www\./, "");
    if (!d || SKIP_WORDS[d] || !DOMAIN_RE.test(d)) return;
    set[d] = 1;
  }

  function extractQuotedDomains(text, out) {
    var re = /["'](?:\*\.)?((?:[a-z0-9-]+\.)+[a-z]{2,63})["']/gi;
    var m;
    while ((m = re.exec(text))) addDomain(out, m[1]);
  }

  function intToIp(n) {
    n = n >>> 0;
    return ((n >>> 24) & 255) + "." + ((n >>> 16) & 255) + "." + ((n >>> 8) & 255) + "." + (n & 255);
  }

  function ipToInt(ip) {
    var p = String(ip || "").split(".");
    if (p.length !== 4) return 0;
    return ((Number(p[0]) << 24) >>> 0) + (Number(p[1]) << 16) + (Number(p[2]) << 8) + Number(p[3]);
  }

  function maskToBits(mask) {
    if (typeof mask === "number" && mask >= 0 && mask <= 32) return mask;
    if (!IPV4_RE.test(String(mask || ""))) return 0;
    var n = ipToInt(mask), bits = 0;
    for (var i = 0; i < 32; i++) {
      if (n & (1 << (31 - i))) bits++;
      else break;
    }
    return bits;
  }

  function parseSpecialCidrs(text) {
    var m = String(text || "").match(/var\s+special\s*=\s*(\[[\s\S]*?\]);/);
    if (!m) return [];
    try {
      var arr = new Function("return (" + m[1] + ")")();
      if (!Array.isArray(arr)) return [];
      return arr.map(function (row) {
        if (!row || !row[0]) return null;
        return { net: String(row[0]), bits: maskToBits(row[1]) };
      }).filter(function (x) { return x && x.net && x.bits; });
    } catch (e) {
      return [];
    }
  }

  function collectFromRuntime(source) {
    var prelude =
      "var domains, d_ipaddr, special, domains_lzp, mask_lzp, az_initialized, table, hash, c, fbtw;\n";
    var tail = "\n;" +
      "if (typeof FindProxyForURL === 'function') {\n" +
      "  try { FindProxyForURL('https://init.invalid/', 'init.invalid'); } catch (e0) {}\n" +
      "}\n" +
      "var _patterns = (typeof patternreplace === 'function') ? " +
      "(function(){ var s = Function.prototype.toString.call(patternreplace); " +
      "var m = s.match(/var patterns = (\\{[\\s\\S]*?\\});/); " +
      "return m ? (new Function('return (' + m[1] + ')'))() : null; })() : null;\n" +
      "function _rev(s){\n" +
      "  if (!_patterns) return s;\n" +
      "  var keys = Object.keys(_patterns).sort(function(a,b){ return b.length - a.length || b.localeCompare(a); });\n" +
      "  s = String(s || '');\n" +
      "  for (var i = 0; i < keys.length; i++) s = s.split(keys[i]).join(_patterns[keys[i]]);\n" +
      "  return s;\n" +
      "}\n" +
      "function _intToIp(n){ n = n >>> 0; return ((n>>>24)&255)+'.'+((n>>>16)&255)+'.'+((n>>>8)&255)+'.'+(n&255); }\n" +
      "var _domains = [], _ips = [];\n" +
      "if (typeof domains === 'object' && domains) {\n" +
      "  var zones = Object.keys(domains);\n" +
      "  for (var z = 0; z < zones.length; z++) {\n" +
      "    var zone = zones[z], byLen = domains[zone];\n" +
      "    if (!byLen || typeof byLen !== 'object') continue;\n" +
      "    var lens = Object.keys(byLen);\n" +
      "    for (var l = 0; l < lens.length; l++) {\n" +
      "      var len = parseInt(lens[l], 10), val = byLen[lens[l]];\n" +
      "      if (typeof val === 'string' && len) {\n" +
      "        for (var i = 0; i + len <= val.length; i += len) _domains.push(_rev(val.slice(i, i + len)) + '.' + zone);\n" +
      "      } else if (Array.isArray(val)) {\n" +
      "        for (var j = 0; j < val.length; j++) _domains.push(_rev(val[j]) + '.' + zone);\n" +
      "      }\n" +
      "    }\n" +
      "  }\n" +
      "}\n" +
      "if (Array.isArray(d_ipaddr)) {\n" +
      "  for (var k = 0; k < d_ipaddr.length; k++) {\n" +
      "    if (typeof d_ipaddr[k] === 'number') _ips.push(_intToIp(d_ipaddr[k]));\n" +
      "  }\n" +
      "}\n" +
      "return { domains: _domains, ips: _ips };\n";

    var factory = new Function(
      "dnsDomainIs", "shExpMatch", "isPlainHostName", "dnsDomainLevels",
      "myIpAddress", "dnsResolve", "isInNet", "convert_addr",
      "localHostOrDomainIs", "isResolvable", "weekdayRange", "dateRange", "timeRange", "alert",
      prelude + source + tail
    );
    return factory(
      function () { return false; },
      function () { return false; },
      function (h) { return String(h || "").indexOf(".") === -1; },
      function (h) { return Math.max(0, String(h || "").split(".").length - 1); },
      function () { return "127.0.0.1"; },
      function () { return null; },
      function () { return false; },
      function (ip) {
        var b = String(ip || "").split(".");
        return ((((Number(b[0]) || 0) * 256) + (Number(b[1]) || 0)) * 256 + (Number(b[2]) || 0)) * 256 + (Number(b[3]) || 0);
      },
      function () { return false; },
      function () { return false; },
      function () { return false; },
      function () { return false; },
      function () { return false; },
      function () {}
    );
  }

  function parsePacToLists(text) {
    var source = String(text || "").replace(/^\uFEFF/, "");
    if (isHtmlDocument(source)) {
      throw new Error("Сервер отдал HTML-страницу (часто IPFS-шлюз), а не PAC. Не сохраняйте файл через «Сохранить как» — добавьте URL списка в расширение, оно скачает PAC само.");
    }
    if (!isPacText(source)) {
      var preview = source.replace(/\s+/g, " ").trim().slice(0, 160);
      throw new Error(preview ? "Ответ не похож на PAC-файл: " + preview : "В ответе нет FindProxyForURL — это не PAC-файл.");
    }

    var exact = {};
    var ips = {};
    extractQuotedDomains(source, exact);

    try {
      var runtime = collectFromRuntime(source);
      (runtime.domains || []).forEach(function (d) { addDomain(exact, d); });
      (runtime.ips || []).forEach(function (ip) {
        if (IPV4_RE.test(ip) && ip.indexOf("0.") !== 0 && ip.indexOf("127.") !== 0) ips[ip] = 1;
      });
    } catch (e) {}

    var cidrs = parseSpecialCidrs(source);
    var domainList = Object.keys(exact).sort();
    var ipList = Object.keys(ips).sort(function (a, b) { return ipToInt(a) - ipToInt(b); });
    if (!domainList.length && !ipList.length && !cidrs.length) {
      throw new Error("Из PAC не удалось получить ни доменов, ни IP.");
    }
    return {
      domains: domainList,
      ips: ipList,
      cidrs: cidrs,
      domainCount: domainList.length,
      ipCount: ipList.length
    };
  }

  function packDomainList(domains) {
    var packed = {};
    (domains || []).forEach(function (d) {
      d = String(d || "").toLowerCase().replace(/^www\./, "");
      var i = d.lastIndexOf(".");
      if (i < 1) return;
      var name = d.slice(0, i), zone = d.slice(i + 1);
      if (!packed[zone]) packed[zone] = {};
      var k = String(name.length);
      packed[zone][k] = (packed[zone][k] || "") + name;
    });
    return packed;
  }

  function matchPackedDomain(host, packed) {
    if (!host || !packed) return false;
    host = String(host || "").toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
    var variants = [host];
    var two = host.match(/([^.]+\.[^.]+)$/);
    var three = host.match(/([^.]+\.[^.]+\.[^.]+)$/);
    if (two) variants.push(two[1]);
    if (three) variants.push(three[1]);
    for (var v = 0; v < variants.length; v++) {
      var s = variants[v];
      var i = s.lastIndexOf(".");
      if (i < 1) continue;
      var name = s.slice(0, i), zone = s.slice(i + 1);
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

  function matchCidr(ip, cidrs) {
    if (!IPV4_RE.test(ip) || !cidrs || !cidrs.length) return false;
    var n = ipToInt(ip);
    for (var i = 0; i < cidrs.length; i++) {
      var row = cidrs[i];
      if (!row) continue;
      var bits = maskToBits(row.bits != null ? row.bits : row.mask);
      if (!bits) continue;
      var net = ipToInt(row.net);
      var mask = bits >= 32 ? 0xFFFFFFFF : ((0xFFFFFFFF << (32 - bits)) >>> 0);
      if ((n & mask) === (net & mask)) return true;
    }
    return false;
  }

  function matchIpLiteral(host, ipSet, cidrs) {
    if (!IPV4_RE.test(host)) return false;
    if (ipSet && (ipSet[host] || ipSet[ipToInt(host)])) return true;
    return matchCidr(host, cidrs);
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
    isHtmlDocument: isHtmlDocument,
    isPacText: isPacText,
    parsePacToLists: parsePacToLists,
    packDomainList: packDomainList,
    matchPackedDomain: matchPackedDomain,
    matchIpLiteral: matchIpLiteral,
    matchCidr: matchCidr,
    ipToInt: ipToInt,
    intToIp: intToIp,
    userProxyToFirefox: userProxyToFirefox,
    userProxyToPac: userProxyToPac,
    addDomain: addDomain,
    DOMAIN_RE: DOMAIN_RE,
    IPV4_RE: IPV4_RE
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.PacParse = api;
})(typeof self !== "undefined" ? self : this);
