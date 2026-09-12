(function (root) {
  "use strict";

  var DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
  var SKIP_WORDS = { function: 1, return: 1, direct: 1, proxy: 1, socks: 1, https: 1, http: 1, host: 1, url: 1 };
  var IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
  var TABLE_LEN_BITS = 18;
  var HASH_MASK = (1 << TABLE_LEN_BITS) - 1;

  function isHtmlDocument(text) {
    var t = String(text || "").replace(/^\uFEFF/, "").trim();
    if (!t) return false;
    return /^<!DOCTYPE\s+html/i.test(t) || /<html[\s>]/i.test(t) || /IPFS Service Worker Gateway/i.test(t);
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

  function extractBalanced(text, start, openCh, closeCh) {
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
      if (c === openCh) depth++;
      else if (c === closeCh) {
        depth--;
        if (depth === 0) return text.slice(start, i + 1);
      }
    }
    return "";
  }

  function parseJsString(text, i) {
    var quote = text[i];
    if (quote !== "\"" && quote !== "'") return null;
    var start = i + 1, j = start, hasEsc = false;
    while (j < text.length) {
      var c = text[j];
      if (c === "\\" && (text[j + 1] === "\n" || text[j + 1] === "\r")) {
        hasEsc = true;
        if (text[j + 1] === "\r" && text[j + 2] === "\n") j += 3;
        else j += 2;
        continue;
      }
      if (c === "\\") { hasEsc = true; j += 2; continue; }
      if (c === quote) {
        var raw = text.slice(start, j);
        var value = hasEsc ? raw.replace(/\\(?:\r\n|\n|\r)/g, "").replace(/\\(.)/g, "$1") : raw;
        return { value: value, next: j + 1 };
      }
      j++;
    }
    return null;
  }

  function findAssign(text, name) {
    var re = new RegExp("(?:(?:^|\\n)(?:var\\s+)?)?" + name + "\\s*=\\s*", "m");
    var m = re.exec(text);
    return m ? m.index + m[0].length : -1;
  }

  function extractAssignedString(text, name) {
    var i = findAssign(text, name);
    if (i < 0) return "";
    while (i < text.length && /\s/.test(text[i])) i++;
    var parsed = parseJsString(text, i);
    return parsed ? parsed.value : "";
  }

  function parseJsStringMap(src) {
    var out = {};
    if (!src) return out;
    var i = 0;
    if (src.charAt(0) === "{") i = 1;
    while (i < src.length) {
      while (i < src.length && /[\s,]/.test(src.charAt(i))) i++;
      if (i >= src.length || src.charAt(i) === "}") break;
      var key = parseJsString(src, i);
      if (!key) break;
      i = key.next;
      while (i < src.length && /\s/.test(src.charAt(i))) i++;
      if (src.charAt(i) !== ":") break;
      i++;
      while (i < src.length && /\s/.test(src.charAt(i))) i++;
      var val = parseJsString(src, i);
      if (!val) break;
      out[key.value] = val.value;
      i = val.next;
    }
    return out;
  }

  function extractPatternMaps(text) {
    var domainPatterns = null, maskPatterns = null;
    var idx = text.search(/function\s+patternreplace\s*\(/);
    if (idx < 0) return { domainPatterns: null, maskPatterns: null };
    var body = extractBalanced(text, text.indexOf("{", idx), "{", "}");
    var pos = 0, seen = 0;
    while (seen < 2) {
      var m = body.indexOf("var patterns =", pos);
      if (m < 0) break;
      var start = body.indexOf("{", m);
      if (start < 0) break;
      var raw = extractBalanced(body, start, "{", "}");
      var map = parseJsStringMap(raw);
      if (!domainPatterns) domainPatterns = map;
      else maskPatterns = map;
      pos = start + raw.length;
      seen++;
    }
    return { domainPatterns: domainPatterns, maskPatterns: maskPatterns };
  }

  function parseDomainsTable(text) {
    var i = findAssign(text, "domains");
    if (i < 0) return null;
    while (i < text.length && /\s/.test(text[i])) i++;
    if (text[i] !== "{") return null;
    var raw = extractBalanced(text, i, "{", "}");
    if (!raw) return null;
    try {
      var json = raw.replace(/([{,]\s*)(\d+)\s*:/g, "$1\"$2\":");
      return JSON.parse(json);
    } catch (e) {
      return null;
    }
  }

  function parseSpecialCidrs(text) {
    var out = [];
    var re = /\["(\d{1,3}(?:\.\d{1,3}){3})",\s*(\d{1,2})\]/g;
    var m;
    while ((m = re.exec(String(text || "")))) {
      out.push({ net: m[1], bits: Number(m[2]) });
    }
    return out;
  }

  function decodeIpList(text) {
    var raw = extractAssignedString(text, "d_ipaddr");
    if (!raw) return [];
    var parts = raw.split(" ");
    var out = [], prev = 0;
    for (var i = 0; i < parts.length; i++) {
      if (!parts[i]) continue;
      var n = parseInt(parts[i], 36);
      if (!isFinite(n)) continue;
      prev = (n + prev) >>> 0;
      out.push(intToIp(prev));
    }
    return out;
  }

  function a2b(a) {
    var b, c, d, e = {}, f = 0, g = 0, h = "", i = String.fromCharCode, j = a.length;
    for (b = 0; 64 > b; b++) e["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(b)] = b;
    for (c = 0; j > c; c++) {
      for (b = e[a.charAt(c)], f = (f << 6) + b, g += 6; g >= 8;) {
        d = 255 & f >>> (g -= 8);
        if (d || j - 2 > c) h += i(d);
      }
    }
    return h;
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

  function createUnlzpState() {
    return { table: new Array(1 << TABLE_LEN_BITS), hash: 0 };
  }

  function unlzp(d, m, lim, state) {
    var mask = 0, maskpos = 0, dpos = 0, out = new Array(8), outpos = 0, outfinal = "";
    var c;
    for (;;) {
      mask = m.charAt(maskpos++);
      if (!mask) break;
      mask = mask.charCodeAt(0);
      outpos = 0;
      for (var i = 0; i < 8; i++) {
        if (mask & (1 << i)) {
          c = state.table[state.hash];
        } else {
          c = d.charAt(dpos++);
          if (!c) break;
          c = c.charCodeAt(0);
          state.table[state.hash] = c;
        }
        out[outpos++] = String.fromCharCode(c);
        state.hash = ((state.hash << 7) ^ c) & HASH_MASK;
      }
      if (outpos === 8) outfinal += out.join("");
      if (outfinal.length >= lim) break;
    }
    if (outpos < 8) outfinal += out.slice(0, outpos).join("");
    return [outfinal, dpos, maskpos];
  }

  function expandLzPacked(domains, domainsLzp, maskLzp, maskPatterns) {
    var packed = {};
    var count = 0;
    if (!domains) return { packed: packed, count: 0 };
    if (domainsLzp && maskLzp) maskLzp = a2b(applyPatterns(maskLzp, maskPatterns));
    var leftover = "";
    var state = domainsLzp ? createUnlzpState() : null;
    var zones = Object.keys(domains);
    for (var z = 0; z < zones.length; z++) {
      var zone = zones[z];
      var byLen = domains[zone];
      if (!byLen || typeof byLen !== "object") continue;
      if (!packed[zone]) packed[zone] = {};
      var lens = Object.keys(byLen);
      for (var l = 0; l < lens.length; l++) {
        var nameLen = parseInt(lens[l], 10);
        var val = byLen[lens[l]];
        var chunk = "";
        if (typeof val === "string") {
          chunk = val;
        } else {
          var totalChars = Number(val);
          if (!nameLen || !totalChars || !state) continue;
          if (leftover.length < totalChars) {
            var reqd = totalChars <= 8192 ? 8192 : totalChars;
            var u = unlzp(domainsLzp, maskLzp, reqd, state);
            domainsLzp = domainsLzp.slice(u[1]);
            maskLzp = maskLzp.slice(u[2]);
            leftover += u[0];
          }
          chunk = leftover.slice(0, totalChars);
          leftover = leftover.slice(totalChars);
        }
        packed[zone][String(nameLen)] = chunk;
        if (nameLen) count += Math.floor(chunk.length / nameLen);
      }
    }
    return { packed: packed, count: count };
  }

  function extractThreePart(text) {
    var m = String(text || "").match(/if\s*\(\s*\/\\\.\(([^)]+)\)\\\.\[\^\\.\]\+\$\/\.test\(host\)/);
    return m ? m[1] : "ru|co|cu|com|info|net|org|gov|edu|int|mil|biz|pp|ne|msk|spb|nnov|od|in|ho|cc|dn|i|tut|v|dp|sl|ddns|dyndns|livejournal|herokuapp|azurewebsites|cloudfront|ucoz|3dn|nov|linode|sl-reverse|kiev|beget|kirov|akadns|scaleway|fastly|hldns|appspot|my1|hwcdn|deviantart|wixmp|wix|netdna-ssl|brightcove|berlogovo|edgecastcdn|trafficmanager|pximg|github|hopto|u-stream|google|keenetic|eu|googleusercontent|3nx|itch|notion|maryno|vercel|pythonanywhere|force|tilda|ggpht|iboards|mybb2|h1n|bdsmlr|narod|sb-cd|4chan|nichost|cv";
  }

  function toShortHost(host, threeRe) {
    host = String(host || "").toLowerCase();
    if (host.charAt(host.length - 1) === ".") host = host.slice(0, -1);
    if (threeRe && threeRe.test(host)) host = host.replace(/(.+)\.([^.]+\.[^.]+\.[^.]+$)/, "$2");
    else host = host.replace(/(.+)\.([^.]+\.[^.]+$)/, "$2");
    if (host.indexOf("www.") === 0) host = host.slice(4);
    return host;
  }

  function indexPacked(packed) {
    var idx = Object.create(null);
    if (!packed) return idx;
    var zones = Object.keys(packed);
    for (var z = 0; z < zones.length; z++) {
      var zone = zones[z];
      var byLen = packed[zone];
      if (!byLen) continue;
      var names = idx[zone] = Object.create(null);
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

  function compilePacList(list) {
    if (!list) return null;
    var extra = list.extra || list.domains || [];
    var extraMap = Object.create(null);
    for (var i = 0; i < extra.length; i++) {
      if (extra[i]) extraMap[extra[i]] = 1;
    }
    var threeRe = null;
    if (list.threePart) {
      try { threeRe = new RegExp("\\.(" + list.threePart + ")\\.[^.]+$"); } catch (e) {}
    }
    return {
      packed: list.packed || null,
      patterns: list.patterns || null,
      patKeys: list.patterns ? Object.keys(list.patterns) : null,
      threePart: list.threePart || "",
      threeRe: threeRe,
      extra: extra,
      extraMap: extraMap,
      idx: list.idx || indexPacked(list.packed)
    };
  }

  var compiledCache = new WeakMap();

  function getCompiled(list) {
    if (!list) return null;
    if (list.idx && list.extraMap) return list;
    var cached = compiledCache.get(list);
    if (cached) return cached;
    cached = compilePacList(list);
    compiledCache.set(list, cached);
    return cached;
  }

  function matchPacHost(host, list) {
    if (!list || !host) return false;
    var c = getCompiled(list);
    if (!c) return false;
    host = String(host).toLowerCase();
    if (c.extraMap[host]) return true;
    var extra = c.extra;
    for (var i = 0; i < extra.length; i++) {
      var d = extra[i];
      if (d && host.length > d.length && host.charCodeAt(host.length - d.length - 1) === 46 && host.indexOf(d, host.length - d.length) === host.length - d.length) return true;
    }
    var shost = toShortHost(host, c.threeRe);
    var dot = shost.lastIndexOf(".");
    if (dot < 1) return false;
    var name = c.patterns ? applyPatterns(shost.slice(0, dot), c.patterns, c.patKeys) : shost.slice(0, dot);
    var names = c.idx[shost.slice(dot + 1)];
    return !!(names && names[name]);
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

    var extra = {};
    extractQuotedDomains(source, extra);
    var maps = extractPatternMaps(source);
    var domainsTable = parseDomainsTable(source);
    var domainsLzp = extractAssignedString(source, "domains_lzp");
    var maskLzp = extractAssignedString(source, "mask_lzp");
    var expanded = expandLzPacked(domainsTable, domainsLzp, maskLzp, maps.maskPatterns);
    var extraList = Object.keys(extra).sort();

    var ips = {};
    var decodedIps = decodeIpList(source);
    for (var k = 0; k < decodedIps.length; k++) {
      var ip = decodedIps[k];
      if (IPV4_RE.test(ip) && ip.indexOf("0.") !== 0 && ip.indexOf("127.") !== 0) ips[ip] = 1;
    }
    var cidrs = parseSpecialCidrs(source);
    var domainCount = expanded.count || extraList.length;
    var ipList = Object.keys(ips);

    if (domainsLzp && domainCount < 100) {
      throw new Error("Не удалось распаковать сжатый PAC (получено только " + domainCount + " доменов).");
    }
    if (!domainCount && !ipList.length && !cidrs.length) {
      throw new Error("Из PAC не удалось получить ни доменов, ни IP.");
    }
    return {
      packed: expanded.packed,
      patterns: maps.domainPatterns || null,
      threePart: extractThreePart(source),
      extra: extraList,
      domains: extraList,
      ips: ipList,
      cidrs: cidrs,
      domainCount: domainCount,
      ipCount: ipList.length
    };
  }

  function compileCidrs(cidrs) {
    var out = [];
    for (var i = 0; i < (cidrs || []).length; i++) {
      var row = cidrs[i];
      if (!row || !row.net) continue;
      var bits = maskToBits(row.bits != null ? row.bits : row.mask);
      if (!bits) continue;
      var net = ipToInt(row.net);
      var mask = bits >= 32 ? 0xFFFFFFFF : ((0xFFFFFFFF << (32 - bits)) >>> 0);
      out.push(net & mask, mask);
    }
    return out;
  }

  function matchCidr(ip, cidrs) {
    if (!IPV4_RE.test(ip) || !cidrs || !cidrs.length) return false;
    var n = ipToInt(ip);
    if (typeof cidrs[0] === "number") {
      for (var i = 0; i < cidrs.length; i += 2) {
        if ((n & cidrs[i + 1]) === cidrs[i]) return true;
      }
      return false;
    }
    for (var j = 0; j < cidrs.length; j++) {
      var row = cidrs[j];
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

  function basicAuthHeader(user, pass) {
    var s = String(user || "") + ":" + String(pass || "");
    return "Basic " + btoa(unescape(encodeURIComponent(s)));
  }

  function userProxyToFirefox(cfg) {
    if (!cfg || !cfg.host || !cfg.port) return { type: "direct" };
    var t = cfg.type === "socks" ? "socks" : (cfg.type === "https" ? "https" : "http");
    var host = String(cfg.host).replace(/^\s+|\s+$/g, "");
    var port = Number(cfg.port);
    if (!host || !(port > 0 && port < 65536)) return { type: "direct" };
    var out = { type: t, host: host, port: port, failoverTimeout: 5 };
    if (t === "socks") {
      out.proxyDNS = true;
      if (cfg.username || cfg.password) {
        out.username = String(cfg.username || "");
        out.password = String(cfg.password || "");
      }
    } else if (cfg.username || cfg.password) {
      out.proxyAuthorizationHeader = basicAuthHeader(cfg.username, cfg.password);
    }
    return out;
  }

  var api = {
    isHtmlDocument: isHtmlDocument,
    isPacText: isPacText,
    parsePacToLists: parsePacToLists,
    compilePacList: compilePacList,
    compileCidrs: compileCidrs,
    matchPacHost: matchPacHost,
    matchIpLiteral: matchIpLiteral,
    ipToInt: ipToInt,
    userProxyToFirefox: userProxyToFirefox,
    IPV4_RE: IPV4_RE
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.PacParse = api;
})(typeof self !== "undefined" ? self : this);
