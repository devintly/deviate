"use strict";

function isIpHost(h) {
  h = String(h || "").replace(/^\*\./, "");
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(h) || h.indexOf(":") >= 0;
}
function isAcceptableHost(h) {
  h = String(h || "");
  if (!h || /\s/.test(h) || /[^\x00-\x7F]/.test(h)) return false;
  if (isIpHost(h)) return true;
  if (!/^[a-z0-9.:\[\]-]+$/i.test(h)) return false;
  return h.indexOf(".") >= 0 && h.indexOf("..") < 0;
}
function normalize(v) {
  const trimmed = String(v || "").trim();
  if (!trimmed || /\s/.test(trimmed)) return "";
  let s = trimmed.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (/\s/.test(s)) return "";
  const wild = s.startsWith("*.");
  if (wild) s = s.slice(2);
  s = s.replace(/^\.+|\.+$/g, "");
  if (!s || !isAcceptableHost(s)) return "";
  if (isIpHost(s)) return s;
  return wild ? "*." + s : s;
}
function parseRules(text) {
  return [...new Set(String(text || "").split("\n").map(normalize).filter(Boolean))];
}
function addHostRules(rules) {
  const exact = {}, suffix = {}, ipMap = {};
  (rules || []).forEach(r => {
    r = normalize(r);
    if (!r) return;
    const wild = r.startsWith("*.");
    const host = wild ? r.slice(2) : r;
    if (!host) return;
    if (isIpHost(host)) {
      exact[host] = 1;
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) ipMap[host] = 1;
      return;
    }
    if (wild) suffix["." + host] = 1;
    else exact[host] = 1;
  });
  return { exact, suffix, ipMap };
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

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const exactOnly = addHostRules(["cdn.example.com"]);
assert(matchMaps("cdn.example.com", exactOnly.exact, exactOnly.suffix), "exact host");
assert(!matchMaps("www.cdn.example.com", exactOnly.exact, exactOnly.suffix), "exact must not cover subdomain");
assert(!matchMaps("example.com", exactOnly.exact, exactOnly.suffix), "exact must not cover parent");

const wild = addHostRules(["*.example.com"]);
assert(matchMaps("example.com", wild.exact, wild.suffix), "wildcard covers apex");
assert(matchMaps("www.example.com", wild.exact, wild.suffix), "wildcard covers www");
assert(matchMaps("cdn.example.com", wild.exact, wild.suffix), "wildcard covers subdomain");
assert(!matchMaps("example.org", wild.exact, wild.suffix), "wildcard must not cover other tld");

const ip = addHostRules(["*.8.8.8.8", "1.2.3.4"]);
assert(matchMaps("8.8.8.8", ip.exact, ip.suffix), "ip from starred input");
assert(matchMaps("1.2.3.4", ip.exact, ip.suffix), "plain ip");
assert(!matchMaps("8.8.8.9", ip.exact, ip.suffix), "other ip");
assert(ip.ipMap["8.8.8.8"] && ip.ipMap["1.2.3.4"], "ips indexed");
assert(normalize("*.1.2.3.4") === "1.2.3.4", "star stripped from ip");
assert(normalize("Example.COM") === "example.com", "plain domain kept exact");
assert(normalize("*.Example.COM") === "*.example.com", "wildcard kept");
assert(normalize("nodot") === "", "hostname without a dot is rejected");
assert(normalize("localhost") === "", "localhost without a dot is rejected");
assert(normalize("foo bar.com") === "", "spaces are rejected");
assert(normalize(" example.com ") === "example.com", "edge spaces are trimmed");
assert(normalize("example..com") === "", "empty label is rejected");
assert(normalize("*.ok.org") === "*.ok.org", "wildcard with a dot kept");
assert(normalize("https://cdn.example.com/path") === "cdn.example.com", "url still normalizes");
assert(parseRules("example.com\nnodot\nfoo bar.com\n*.ok.org\n\nexample.com").join(",") === "example.com,*.ok.org", "editor drops bad lines");
assert(normalize("пример.com") === "", "cyrillic domain is rejected");
assert(normalize("xn--e1afmkfd.com") === "xn--e1afmkfd.com", "punycode kept");

function addListTargets(domains) {
  const exact = {}, suffix = {};
  (domains || []).forEach(d => {
    d = normalize(d);
    if (!d) return;
    if (d.startsWith("*.")) suffix["." + d.slice(2)] = 1;
    else { exact[d] = 1; suffix["." + d] = 1; }
  });
  return { exact, suffix };
}
const fromList = addListTargets(["example.com"]);
assert(matchMaps("example.com", fromList.exact, fromList.suffix), "list apex");
assert(matchMaps("cdn.example.com", fromList.exact, fromList.suffix), "list parent rule covers subdomain");
assert(matchMaps("a.b.example.com", fromList.exact, fromList.suffix), "list parent rule covers nested subdomain");

console.log("test-host-rules: ok");
