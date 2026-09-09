#!/usr/bin/env node
"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const PacParse = require("../pac-parse.js");

function ok(cond, msg) {
  assert.ok(cond, msg);
  console.log("ok", msg);
}

const html = `<!DOCTYPE html>
<html lang="en"><head><title>IPFS Service Worker Gateway</title></head>
<body><p>not a pac</p></body></html>`;
ok(PacParse.isHtmlDocument(html), "detects IPFS/HTML wrapper");
ok(!PacParse.isPacText(html), "HTML is not PAC");
assert.throws(() => PacParse.parsePacToLists(html), /HTML/);

const simple = `
function FindProxyForURL(url, host) {
  if (dnsDomainIs(host, "instagram.com") || shExpMatch(host, "*.facebook.com")) {
    return "PROXY 127.0.0.1:8080";
  }
  return "DIRECT";
}
`;
const simpleLists = PacParse.parsePacToLists(simple);
ok(simpleLists.domains.includes("instagram.com"), "quoted instagram.com");
ok(simpleLists.domains.includes("facebook.com"), "quoted facebook.com");

const packed = PacParse.packDomainList(["instagram.com", "facebook.com", "t.co"]);
ok(PacParse.matchPackedDomain("www.instagram.com", packed), "packed matches www.instagram.com");
ok(PacParse.matchPackedDomain("facebook.com", packed), "packed matches facebook.com");
ok(!PacParse.matchPackedDomain("example.com", packed), "packed misses example.com");

ok(PacParse.matchIpLiteral("8.8.8.8", { "8.8.8.8": 1 }, []), "exact IP");
ok(PacParse.matchIpLiteral("68.171.224.10", {}, [{ net: "68.171.224.0", bits: 19 }]), "CIDR IP");
ok(!PacParse.matchIpLiteral("1.1.1.1", {}, [{ net: "68.171.224.0", bits: 19 }]), "CIDR miss");

const sample = path.join("/tmp/pac-samples/orig.pac");
if (fs.existsSync(sample)) {
  const lists = PacParse.parsePacToLists(fs.readFileSync(sample, "utf8"));
  ok(lists.domainCount > 100000, "AntiZapret PAC yields a large domain list: " + lists.domainCount);
  ok(lists.ipCount > 1000, "AntiZapret PAC yields IP list: " + lists.ipCount);
  ok(lists.domains.includes("instagram.com"), "contains instagram.com");
  ok(lists.domains.includes("twitter.com"), "contains twitter.com");
  ok(lists.domains.includes("rutor.info") || lists.domains.includes("rutor.org"), "contains rutor");
  ok(lists.domains.some(function (d) { return /^rutracker\./.test(d); }), "contains rutracker");
  ok(lists.cidrs.length >= 1, "contains CIDR ranges");
  ok(!/new Function|eval\(/.test(fs.readFileSync(path.join(__dirname, "../pac-parse.js"), "utf8")), "parser has no eval");
  const packedAz = PacParse.packDomainList(lists.domains);
  ok(PacParse.matchPackedDomain("www.instagram.com", packedAz), "packed AntiZapret matches instagram");
} else {
  console.log("skip real AntiZapret sample (file missing)");
}

console.log("all tests passed");
