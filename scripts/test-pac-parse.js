#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const PAC_PARSE = fs.existsSync(path.join(ROOT, "src", "common", "pac-parse.js"))
  ? path.join(ROOT, "src", "common", "pac-parse.js")
  : path.join(ROOT, "pac-parse.js");
const SAMPLES = path.join("/tmp", "pac-samples");

function loadPacParse() {
  const code = fs.readFileSync(PAC_PARSE, "utf8");
  const sandbox = { console, module: { exports: {} } };
  sandbox.exports = sandbox.module.exports;
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox, { filename: PAC_PARSE });
  return sandbox.PacParse || sandbox.module.exports;
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function run() {
  const api = loadPacParse();
  const origPath = path.join(SAMPLES, "orig.pac");
  if (fs.existsSync(origPath)) {
    const orig = fs.readFileSync(origPath, "utf8");

    const t0 = Date.now();
    const lists = api.parsePacToLists(orig);
    const elapsed = Date.now() - t0;
    const packedJson = JSON.stringify(lists.packed || {}).length;
    console.log("parse orig.pac:", elapsed, "ms");
    console.log("packed domains:", lists.domainCount, "ips:", lists.ipCount, "packed JSON:", packedJson);

    assert(elapsed < 8000, "parsePacToLists too slow: " + elapsed + "ms");
    assert(lists.packed && typeof lists.packed === "object", "packed domains missing");
    assert(lists.domainCount > 200000, "too few packed domains: " + lists.domainCount);
    assert(lists.ipCount > 5000, "too few ips: " + lists.ipCount);
    assert(lists.extra.includes("instagram.com"), "fbtw extra missing instagram.com");
    assert(lists.domains.length < 100, "domains must stay compact extra list, got " + lists.domains.length);
    const t1 = Date.now();
    const compiled = api.compilePacList(lists);
    for (let i = 0; i < 4000; i++) {
      if (!api.matchPacHost("rutor.info", compiled)) throw new Error("compiled miss");
      if (api.matchPacHost("example.com", compiled)) throw new Error("compiled false positive");
    }
    const matchMs = Date.now() - t1;
    console.log("4000 match pairs:", matchMs, "ms");
    assert(matchMs < 800, "PAC match too slow: " + matchMs + "ms");
    assert(api.matchPacHost("rutor.info", lists), "rutor.info not packed");
    assert(api.matchPacHost("www.rutor.info", lists), "www.rutor.info not packed");
    assert(api.matchPacHost("rutracker.org", lists), "rutracker.org not packed");
    assert(api.matchPacHost("instagram.com", lists), "instagram.com not packed");
    assert(api.matchPacHost("x.com", lists), "x.com not packed");
    assert(!api.matchPacHost("example.com", lists), "example.com should not match packed");
    assert(lists.ips.includes("1.179.201.18"), "expected decoded IP missing");
  } else {
    console.log("large PAC benchmark skipped; deterministic PAC checks continue");
  }

  const html = "<!DOCTYPE html><html><body>IPFS Service Worker Gateway</body></html>";
  assert(api.isHtmlDocument(html), "HTML gateway should be detected");
  let threw = false;
  try { api.parsePacToLists(html); } catch (e) { threw = /HTML/i.test(String(e.message)); }
  assert(threw, "HTML document must not parse as PAC");

  const tiny = 'function FindProxyForURL(url, host){ if(dnsDomainIs(host, "example.org") || dnsDomainIs(host, "example.org") || dnsDomainIs(host, "*.example.org") || dnsDomainIs(host, "www.example.org") || dnsDomainIs(host, "second.net")) return "PROXY 1:2"; return "DIRECT"; }';
  const tinyLists = api.parsePacToLists(tiny);
  assert(tinyLists.extra.includes("example.org"), "quoted domain missing from tiny PAC");
  assert(tinyLists.extra.includes("second.net"), "second.net missing from tiny PAC");
  assert(tinyLists.domainCount === 2, "tiny PAC duplicate domains must be deduplicated: got " + tinyLists.domainCount);
  assert(tinyLists.extra.length === 2, "tiny PAC extra list must contain exactly 2 unique domains: got " + tinyLists.extra.length);
  assert(api.matchPacHost("example.org", tinyLists), "tiny PAC host should match extra");
  assert(api.matchPacHost("www.example.org", tinyLists), "www.example.org should match extra");

  const packedWithExtra = 'var domains = {"org": {"7": "example"}}; function FindProxyForURL(url, host){ if(dnsDomainIs(host, "example.org") || dnsDomainIs(host, "newsite.org")) return "PROXY 1:2"; return "DIRECT"; }';
  const parsedOverlap = api.parsePacToLists(packedWithExtra);
  assert(parsedOverlap.domainCount === 2, "overlap between packed and extra must not count duplicate: got " + parsedOverlap.domainCount);

  const code = fs.readFileSync(PAC_PARSE, "utf8");
  assert(!/\bnew Function\b/.test(code), "pac-parse must not use new Function");
  assert(!/\beval\s*\(/.test(code), "pac-parse must not use eval");

  console.log("ok");
}

run();
