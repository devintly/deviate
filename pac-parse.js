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
    var quote = text[i++];
    if (quote !== "\"" && quote !== "'") return null;
    var out = "";
    while (i < text.length) {
      var c = text[i++];
      if (c === "\\" && (text[i] === "\n" || text[i] === "\r")) {
        if (text[i] === "\r" && text[i + 1] === "\n") i++;
        i++;
        continue;
      }
      if (c === "\\") {
        if (i >= text.length) break;
        var n = text[i++];
        if (n === "n") out += "\n";
        else if (n === "r") out += "\r";
        else if (n === "t") out += "\t";
        else out += n;
        continue;
      }
      if (c === quote) return { value: out, next: i };
      out += c;
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

  function applyPatterns(s, patterns) {
    if (!patterns) return s;
    var keys = Object.keys(patterns);
    for (var i = 0; i < keys.length; i++) {
      var token = keys[i];
      s = String(s).split(patterns[token]).join(token);
    }
    return s;
  }

  function reversePatterns(s, patterns) {
    if (!patterns) return s;
    var keys = Object.keys(patterns).sort(function (a, b) {
      return b.length - a.length || b.localeCompare(a);
    });
    s = String(s || "");
    for (var i = 0; i < keys.length; i++) s = s.split(keys[i]).join(patterns[keys[i]]);
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

  function expandLzDomains(domains, domainsLzp, maskLzp, domainPatterns, maskPatterns) {
    var packed = [];
    if (!domains || !domainsLzp) return packed;
    if (maskLzp) maskLzp = a2b(applyPatterns(maskLzp, maskPatterns));
    var leftover = "";
    var state = createUnlzpState();
    var zones = Object.keys(domains);
    for (var z = 0; z < zones.length; z++) {
      var zone = zones[z];
      var byLen = domains[zone];
      if (!byLen || typeof byLen !== "object") continue;
      var lens = Object.keys(byLen);
      for (var l = 0; l < lens.length; l++) {
        var nameLen = parseInt(lens[l], 10);
        var val = byLen[lens[l]];
        if (typeof val === "string") {
          packed.push({ zone: zone, chunk: val, len: nameLen });
          continue;
        }
        var totalChars = Number(val);
        if (!nameLen || !totalChars) continue;
        if (leftover.length < totalChars) {
          var reqd = totalChars <= 8192 ? 8192 : totalChars;
          var u = unlzp(domainsLzp, maskLzp, reqd, state);
          domainsLzp = domainsLzp.slice(u[1]);
          maskLzp = maskLzp.slice(u[2]);
          leftover += u[0];
        }
        packed.push({ zone: zone, chunk: leftover.slice(0, totalChars), len: nameLen });
        leftover = leftover.slice(totalChars);
      }
    }
    var out = [];
    for (var p = 0; p < packed.length; p++) {
      var item = packed[p];
      var chunk = item.chunk;
      var len = item.len || 0;
      if (typeof chunk !== "string" || !len) continue;
      for (var i = 0; i + len <= chunk.length; i += len) {
        out.push(reversePatterns(chunk.slice(i, i + len), domainPatterns) + "." + item.zone);
      }
    }
    return out;
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
    extractQuotedDomains(source, exact);

    var domainsTable = parseDomainsTable(source);
    var domainsLzp = extractAssignedString(source, "domains_lzp");
    var maskLzp = extractAssignedString(source, "mask_lzp");
    var maps = extractPatternMaps(source);
    var expanded = expandLzDomains(domainsTable, domainsLzp, maskLzp, maps.domainPatterns, maps.maskPatterns);
    for (var i = 0; i < expanded.length; i++) addDomain(exact, expanded[i]);

    var ips = {};
    var decodedIps = decodeIpList(source);
    for (var k = 0; k < decodedIps.length; k++) {
      var ip = decodedIps[k];
      if (IPV4_RE.test(ip) && ip.indexOf("0.") !== 0 && ip.indexOf("127.") !== 0) ips[ip] = 1;
    }

    var cidrs = parseSpecialCidrs(source);
    var domainList = Object.keys(exact).sort();
    var ipList = Object.keys(ips).sort(function (a, b) { return ipToInt(a) - ipToInt(b); });

    if (domainsLzp && domainList.length < 100) {
      throw new Error("Не удалось распаковать сжатый PAC (получено только " + domainList.length + " доменов). Обновите дополнение и нажмите «Обновить списки».");
    }
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
