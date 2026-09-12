#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const COMMON = path.join(ROOT, "src", "common");

function load(file, sandbox) {
  vm.runInContext(fs.readFileSync(path.join(COMMON, file), "utf8"), sandbox, { filename: file });
}

const sandbox = { console, module: { exports: {} }, self: {}, URL, Set };
sandbox.exports = sandbox.module.exports;
vm.createContext(sandbox);
load("pac-parse.js", sandbox);
load("host-rules.js", sandbox);
const api = sandbox.HostRules || sandbox.self.HostRules || sandbox.module.exports;

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const exactOnly = { exact: {}, suffix: {}, ipMap: {} };
api.addHostRules(["cdn.example.com"], exactOnly.exact, exactOnly.suffix, exactOnly.ipMap);
assert(api.matchMaps("cdn.example.com", exactOnly.exact, exactOnly.suffix), "exact host");
assert(!api.matchMaps("www.cdn.example.com", exactOnly.exact, exactOnly.suffix), "exact host must not cover www alias without wildcard");
assert(!api.matchMaps("api.cdn.example.com", exactOnly.exact, exactOnly.suffix), "exact must not cover other subdomain");
assert(!api.matchMaps("example.com", exactOnly.exact, exactOnly.suffix), "exact must not cover parent");

const wild = { exact: {}, suffix: {}, ipMap: {} };
api.addHostRules(["*.example.com"], wild.exact, wild.suffix, wild.ipMap);
assert(api.matchMaps("example.com", wild.exact, wild.suffix), "wildcard covers apex");
assert(api.matchMaps("www.example.com", wild.exact, wild.suffix), "wildcard covers www");
assert(api.matchMaps("cdn.example.com", wild.exact, wild.suffix), "wildcard covers subdomain");
assert(!api.matchMaps("example.org", wild.exact, wild.suffix), "wildcard must not cover other tld");

const ip = { exact: {}, suffix: {}, ipMap: {} };
api.addHostRules(["*.8.8.8.8", "1.2.3.4"], ip.exact, ip.suffix, ip.ipMap);
assert(api.matchMaps("8.8.8.8", ip.exact, ip.suffix), "ip from starred input");
assert(api.matchMaps("1.2.3.4", ip.exact, ip.suffix), "plain ip");
assert(!api.matchMaps("8.8.8.9", ip.exact, ip.suffix), "other ip");
assert(ip.ipMap["8.8.8.8"] && ip.ipMap["1.2.3.4"], "ips indexed");
assert(api.normalizeRule("*.1.2.3.4") === "1.2.3.4", "star stripped from ip");
assert(api.normalizeRule("Example.COM") === "example.com", "plain domain kept exact");
assert(api.normalizeRule("*.Example.COM") === "*.example.com", "wildcard kept");
assert(api.normalizeRule("nodot") === "", "hostname without a dot is rejected");
assert(api.normalizeRule("localhost") === "", "localhost without a dot is rejected");
assert(api.normalizeRule("foo bar.com") === "", "spaces are rejected");
assert(api.normalizeRule(" example.com ") === "example.com", "edge spaces are trimmed");
assert(api.normalizeRule("example..com") === "", "empty label is rejected");
assert(api.normalizeRule("*.ok.org") === "*.ok.org", "wildcard with a dot kept");
assert(api.normalizeRule("https://cdn.example.com/path") === "cdn.example.com", "url still normalizes");
assert(api.normalizeRule("https://cdn.example.com:8443/path") === "cdn.example.com", "URL port is stripped");
assert(api.normalizeRule("cdn.example.com:8443") === "cdn.example.com", "plain host port is stripped");
assert(api.normalizeRule("httpx://example.com") === "", "non-HTTP URL is rejected");
assert(api.normalizeRule("abc:def") === "", "invalid colon host is rejected");
assert(api.normalizeRule("[2001:db8::1]") === "2001:db8::1", "IPv6 literal is accepted");
assert(api.normalizeRule("пример.com") === "", "cyrillic domain is rejected");
assert(api.normalizeRule("xn--e1afmkfd.com") === "xn--e1afmkfd.com", "punycode kept");

const fromList = { exact: {}, suffix: {}, ip: {}, cidr: [] };
api.addListTargets({ domains: ["example.com"] }, fromList.exact, fromList.suffix, fromList.ip, fromList.cidr);
assert(api.matchMaps("example.com", fromList.exact, fromList.suffix), "list apex");
assert(api.matchMaps("cdn.example.com", fromList.exact, fromList.suffix), "list parent rule covers subdomain");
assert(api.matchMaps("a.b.example.com", fromList.exact, fromList.suffix), "list parent rule covers nested subdomain");

const maps = api.rebuildMaps(["cdn.example.com"], ["skip.test"], [{
  enabled: true,
  format: "txt",
  domains: ["listed.example"],
  ips: ["9.9.9.9"],
  cidrs: []
}]);
assert(api.hostIsProxied("cdn.example.com", true, maps, false), "user proxy rule");
assert(!api.hostIsProxied("www.cdn.example.com", true, maps, false), "user exact does not cover www alias");
assert(!api.hostIsProxied("api.cdn.example.com", true, maps, false), "user exact does not cover other subdomain");
assert(api.hostIsProxied("listed.example", true, maps, false), "list domain");
assert(api.hostIsProxied("a.listed.example", true, maps, false), "list covers subdomain");
assert(!api.hostIsProxied("skip.test", true, maps, false), "direct rule wins");
assert(!api.hostIsProxied("cdn.example.com", false, maps, false), "disabled extension");
assert(!api.ruleMatchesHost("www.example.com", "example.com"), "UI matcher does not match www subdomain for exact rule");
assert(api.ruleMatchesHost("www.example.com", "*.example.com"), "UI matcher matches www subdomain for wildcard rule");

const remembered = {};
assert(api.rememberHost(remembered, 1, "one.example", 1) === "one.example", "first host remembered");
assert(api.rememberHost(remembered, 1, "one.example", 1) === "one.example", "existing host survives limit");
assert(api.rememberHost(remembered, 1, "two.example", 1) === null, "new host rejected at limit");

console.log("test-host-rules: ok");
