(function (root) {
  "use strict";

  var TAB_HOST_LIMIT = 200;
  var IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
  var MULTI_SUFFIX = {
    "ac.uk":1,"co.uk":1,"gov.uk":1,"ltd.uk":1,"me.uk":1,"net.uk":1,"org.uk":1,"plc.uk":1,"sch.uk":1,
    "com.au":1,"net.au":1,"org.au":1,"edu.au":1,"gov.au":1,"asn.au":1,"id.au":1,
    "co.nz":1,"net.nz":1,"org.nz":1,"co.jp":1,"ne.jp":1,"or.jp":1,"ac.jp":1,"go.jp":1,
    "com.br":1,"net.br":1,"org.br":1,"com.tr":1,"com.ua":1,"co.ua":1,"org.ua":1,
    "com.cn":1,"net.cn":1,"org.cn":1,"com.tw":1,"com.hk":1,"co.kr":1,"com.mx":1,
    "co.za":1,"co.in":1,"net.in":1,"org.in":1,"co.il":1,"com.sg":1
  };

  function getPacParse() {
    if (typeof PacParse !== "undefined") return PacParse;
    if (root && root.PacParse) return root.PacParse;
    if (typeof globalThis !== "undefined" && globalThis.PacParse) return globalThis.PacParse;
    return null;
  }

  function normalizeIpv6(value) {
    var raw = String(value || "").replace(/^\[|\]$/g, "");
    if (raw.indexOf(":") < 0 || /[^0-9a-f:.]/i.test(raw)) return "";
    try {
      var host = new URL("http://[" + raw + "]/").hostname;
      return host && host.indexOf(":") >= 0 ? host.toLowerCase().replace(/^\[|\]$/g, "") : "";
    } catch (e) {
      return "";
    }
  }

  function isIpHost(h) {
    h = String(h || "").replace(/^\*\./, "");
    return IPV4_RE.test(h) || !!normalizeIpv6(h);
  }

  function isIgnoredHost(h) {
    h = String(h || "").trim().toLowerCase().replace(/^\*\./, "").replace(/^\[|\]$/g, "");
    if (!h) return true;
    if (h === "localhost" || h === "0.0.0.0" || h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
    if (h === "127.0.0.1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
    return false;
  }

  function isAcceptableHost(h) {
    h = String(h || "");
    if (!h || /\s/.test(h) || /[^\x00-\x7F]/.test(h)) return false;
    if (isIpHost(h)) return true;
    if (/^\d+(?:\.\d+){3}$/.test(h)) return false;
    if (!/^[a-z0-9.-]+$/i.test(h)) return false;
    if (h.length > 253 || h.indexOf(".") < 0 || h.indexOf("..") >= 0) return false;
    return h.split(".").every(function (label) {
      return label.length > 0 && label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label);
    });
  }

  function normalizeRule(rule) {
    var trimmed = String(rule || "").trim();
    if (!trimmed || /\s/.test(trimmed)) return "";
    var s = trimmed.toLowerCase();
    if (/^https?:\/\//.test(s)) {
      try { s = new URL(s).hostname; }
      catch (e) { return ""; }
    } else {
      s = s.replace(/\/.*$/, "");
      var hostPort = s.match(/^([^:]+):(\d+)$/);
      if (hostPort) s = hostPort[1];
    }
    if (/\s/.test(s)) return "";
    var wild = s.indexOf("*.") === 0;
    if (wild) s = s.slice(2);
    s = s.replace(/^\.+|\.+$/g, "");
    var ipv6 = normalizeIpv6(s);
    if (ipv6) return ipv6;
    if (!s || !isAcceptableHost(s)) return "";
    if (isIpHost(s)) return s;
    return wild ? "*." + s : s;
  }

  function canonHost(host) {
    host = String(host || "").toLowerCase();
    if (!host) return "";
    var ipv6 = normalizeIpv6(host);
    if (ipv6) return ipv6;
    if (host.charCodeAt(host.length - 1) === 46) host = host.slice(0, -1);
    if (host.charCodeAt(0) === 46) host = host.slice(1);
    return host;
  }

  function addHostRules(rules, exact, suffix, ipMap) {
    (rules || []).forEach(function (r) {
      r = normalizeRule(r);
      if (!r) return;
      var wild = r.indexOf("*.") === 0;
      var host = wild ? r.slice(2) : r;
      if (!host) return;
      if (isIpHost(host)) {
        exact[host] = 1;
        if (ipMap && IPV4_RE.test(host)) ipMap[host] = 1;
        return;
      }
      if (wild) suffix["." + host] = 1;
      else exact[host] = 1;
    });
  }

  function addListTargets(list, exact, suffix, ipMap, cidrs) {
    (list.domains || []).forEach(function (d) {
      d = normalizeRule(d);
      if (!d) return;
      if (d.indexOf("*.") === 0) suffix["." + d.slice(2)] = 1;
      else {
        exact[d] = 1;
        suffix["." + d] = 1;
      }
    });
    (list.ips || []).forEach(function (ip) {
      ip = String(ip || "").trim();
      if (IPV4_RE.test(ip)) ipMap[ip] = 1;
    });
    var PP = getPacParse();
    var compiled = PP ? PP.compileCidrs(list.cidrs) : [];
    for (var i = 0; i < compiled.length; i++) cidrs.push(compiled[i]);
  }

  function assignMap(dst, src) {
    for (var k in src) dst[k] = src[k];
  }

  function matchMaps(host, exact, suffix) {
    if (!host) return false;
    host = host.toLowerCase();
    if (exact[host]) return true;
    var parts = host.split(".");
    var current = "";
    for (var i = parts.length - 1; i >= 0; i--) {
      current = "." + parts[i] + current;
      if (suffix[current]) return true;
    }
    return false;
  }

  function ruleMatchesHost(host, rule) {
    host = canonHost(host);
    rule = normalizeRule(rule);
    if (!host || !rule) return false;
    if (rule.indexOf("*.") === 0) {
      var base = rule.slice(2);
      return host === base || host.length > base.length && host.slice(-base.length - 1) === "." + base;
    }
    return host === rule;
  }

  function coveringRule(host, proxyRules, directRules) {
    host = canonHost(host);
    var best = { action: "", rule: "" };
    var bestLen = -1;
    function consider(list, action) {
      (list || []).forEach(function (rule) {
        var normalized = normalizeRule(rule);
        if (!normalized || !ruleMatchesHost(host, normalized)) return;
        var base = normalized.replace(/^\*\./, "");
        if (base === host) return;
        if (base.length > bestLen || (base.length === bestLen && action === "direct")) {
          bestLen = base.length;
          best = { action: action, rule: normalized };
        }
      });
    }
    consider(proxyRules, "proxy");
    consider(directRules, "direct");
    return best;
  }

  function apexDomain(host) {
    var h = normalizeRule(host).replace(/^\*\./, "");
    if (!h || isIpHost(h)) return h;
    var parts = h.split(".").filter(Boolean);
    if (parts.length <= 2) return h;
    var last2 = parts.slice(-2).join(".");
    return MULTI_SUFFIX[last2] && parts.length >= 3 ? parts.slice(-3).join(".") : last2;
  }

  function hasIpRules(maps) {
    var k;
    for (k in maps.pIp) return true;
    for (k in maps.dIp) return true;
    for (k in maps.pE) if (k.indexOf(":") >= 0) return true;
    for (k in maps.dE) if (k.indexOf(":") >= 0) return true;
    return !!(maps.pCidr && maps.pCidr.length);
  }

  function rebuildMaps(proxyRules, directRules, proxyLists) {
    var pE = {}, pS = {}, dE = {}, dS = {};
    var pIp = {}, dIp = {}, pCidr = [];
    var pPac = [];
    var compiledLists = [];
    var viaProxyHosts = {};

    addHostRules(proxyRules, pE, pS, pIp);
    addHostRules(directRules, dE, dS, dIp);

    (proxyLists || []).forEach(function (list) {
      if (!list || list.enabled === false) return;
      if (list.viaProxy && list.url) {
        try {
          var u = new URL(list.url);
          if (u.hostname) viaProxyHosts[u.hostname.toLowerCase()] = 1;
        } catch (e) {}
      }
      var lExact = {}, lSuffix = {}, lIp = {}, lCidr = [];
      var lPac = null;
      var targets = list;
      var PP = getPacParse();
      if (list.format === "pac" && list.packed && PP) {
        lPac = PP.compilePacList(list);
        pPac.push(lPac);
        targets = { ips: list.ips, cidrs: list.cidrs, domains: list.extra || [] };
      }
      addListTargets(targets, lExact, lSuffix, lIp, lCidr);
      assignMap(pE, lExact);
      assignMap(pS, lSuffix);
      assignMap(pIp, lIp);
      for (var i = 0; i < lCidr.length; i++) pCidr.push(lCidr[i]);
      compiledLists.push({ list: list, pac: lPac, exact: lExact, suffix: lSuffix, ip: lIp, cidr: lCidr });
    });

    return {
      pE: pE, pS: pS, dE: dE, dS: dS,
      pIp: pIp, dIp: dIp, pCidr: pCidr, pPac: pPac,
      compiledLists: compiledLists,
      viaProxyHosts: viaProxyHosts
    };
  }

  function isDirectHost(host, maps) {
    if (matchMaps(host, maps.dE, maps.dS)) return true;
    var PP = getPacParse();
    return !!(PP && PP.matchIpLiteral(host, maps.dIp, []));
  }

  function isProxiedHost(host, maps) {
    if (matchMaps(host, maps.pE, maps.pS)) return true;
    var PP = getPacParse();
    if (PP && PP.matchIpLiteral(host, maps.pIp, maps.pCidr)) return true;
    var pacs = maps.pPac || [];
    for (var i = 0; i < pacs.length; i++) {
      if (PP && PP.matchPacHost(host, pacs[i])) return true;
    }
    return false;
  }

  function hostIsProxied(host, enabled, maps) {
    if (!enabled || !host) return false;
    host = canonHost(host);
    if (!host) return false;
    if (isDirectHost(host, maps)) return false;
    return isProxiedHost(host, maps);
  }

  function listLabel(list) {
    var name = String((list && list.name) || "").trim();
    if (name) return name;
    try { return new URL(list.url).hostname; } catch (e) {}
    return String((list && list.url) || "список");
  }

  function findCoveringList(host, compiledLists) {
    if (!host) return null;
    host = String(host).toLowerCase();
    var PP = getPacParse();
    for (var i = 0; i < (compiledLists || []).length; i++) {
      var entry = compiledLists[i];
      if (entry.pac && PP && PP.matchPacHost(host, entry.pac)) return entry.list;
      if (matchMaps(host, entry.exact, entry.suffix) || (PP && PP.matchIpLiteral(host, entry.ip, entry.cidr))) return entry.list;
    }
    return null;
  }

  function listedParentHost(host, compiledLists) {
    var parts = String(host || "").toLowerCase().split(".").filter(Boolean);
    for (var i = 1; i <= parts.length - 2; i++) {
      var parent = parts.slice(i).join(".");
      if (findCoveringList(parent, compiledLists)) return parent;
    }
    return "";
  }

  function coverPayload(host, compiledLists) {
    host = canonHost(normalizeRule(host).replace(/^\*\./, ""));
    var parent = listedParentHost(host, compiledLists);
    var list = findCoveringList(host, compiledLists) || (parent ? findCoveringList(parent, compiledLists) : null);
    var parentRule = "";
    if (parent) parentRule = isIpHost(parent) ? parent : "*." + parent;
    return {
      listed: !!list,
      listedParent: !!parent,
      listedParentRule: parentRule,
      listName: list ? listLabel(list) : ""
    };
  }

  function coverMany(hosts, compiledLists) {
    var covers = {};
    (hosts || []).forEach(function (h) {
      var host = canonHost(normalizeRule(h).replace(/^\*\./, ""));
      if (!host || covers[host]) return;
      covers[host] = coverPayload(host, compiledLists);
    });
    return covers;
  }

  function isOwnPage(url, base) {
    var s = String(url || "");
    if (!s) return false;
    return !!(base && s.indexOf(base) === 0);
  }

  function isWebTab(tab, base) {
    if (!tab || isOwnPage(tab.url, base)) return false;
    try {
      var p = new URL(tab.url).protocol;
      return p === "http:" || p === "https:";
    } catch (e) {
      return false;
    }
  }

  function rememberHost(bucket, tabId, host, limit) {
    if (tabId == null || tabId < 0 || !host) return null;
    host = canonHost(host);
    if (!host || isIgnoredHost(host)) return null;
    var set = bucket[tabId];
    if (!set) {
      set = new Set();
      bucket[tabId] = set;
    }
    if (!set.has(host) && set.size >= (limit || TAB_HOST_LIMIT)) return null;
    set.add(host);
    return host;
  }

  function buildDomainTree(hosts, apex) {
    apex = String(apex || "").toLowerCase();
    var rawHosts = (hosts || []).map(function (h) {
      return String(h || "").trim().toLowerCase();
    }).filter(function (h) {
      return h && h !== apex;
    });

    var subHostsSet = new Set();
    rawHosts.forEach(function (h) {
      subHostsSet.add(h);
      if (apex && h.length > apex.length && h.endsWith("." + apex)) {
        var prefix = h.slice(0, -(apex.length + 1));
        var parts = prefix.split(".");
        var curr = apex;
        for (var i = parts.length - 1; i > 0; i--) {
          curr = parts[i] + "." + curr;
          subHostsSet.add(curr);
        }
      }
    });

    var uniqueSubs = Array.from(subHostsSet);
    var candidateParents = [apex].concat(uniqueSubs);
    var nodeMap = {};
    uniqueSubs.forEach(function (h) {
      nodeMap[h] = { host: h, children: [] };
    });
    var roots = [];
    uniqueSubs.forEach(function (h) {
      var bestParent = apex;
      var bestLen = apex.length;
      candidateParents.forEach(function (p) {
        if (p === h) return;
        if (h.length > p.length && h.endsWith("." + p)) {
          if (p.length > bestLen) {
            bestParent = p;
            bestLen = p.length;
          }
        }
      });
      if (bestParent === apex) {
        roots.push(nodeMap[h]);
      } else {
        var parentNode = nodeMap[bestParent];
        if (parentNode) parentNode.children.push(nodeMap[h]);
        else roots.push(nodeMap[h]);
      }
    });
    function sortNode(n) {
      n.children.sort(function (a, b) { return a.host.localeCompare(b.host); });
      n.children.forEach(sortNode);
    }
    roots.sort(function (a, b) { return a.host.localeCompare(b.host); });
    roots.forEach(sortNode);
    return roots;
  }

  var api = {
    TAB_HOST_LIMIT: TAB_HOST_LIMIT,
    isIpHost: isIpHost,
    isIgnoredHost: isIgnoredHost,
    isAcceptableHost: isAcceptableHost,
    normalizeRule: normalizeRule,
    canonHost: canonHost,
    addHostRules: addHostRules,
    addListTargets: addListTargets,
    matchMaps: matchMaps,
    ruleMatchesHost: ruleMatchesHost,
    coveringRule: coveringRule,
    apexDomain: apexDomain,
    hasIpRules: hasIpRules,
    rebuildMaps: rebuildMaps,
    isDirectHost: isDirectHost,
    isProxiedHost: isProxiedHost,
    hostIsProxied: hostIsProxied,
    listLabel: listLabel,
    findCoveringList: findCoveringList,
    coverPayload: coverPayload,
    coverMany: coverMany,
    isOwnPage: isOwnPage,
    isWebTab: isWebTab,
    rememberHost: rememberHost,
    buildDomainTree: buildDomainTree
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.HostRules = api;
})(typeof self !== "undefined" ? self : this);
