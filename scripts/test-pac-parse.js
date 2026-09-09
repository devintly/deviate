#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const PAC_PARSE = path.join(ROOT, "FireFox", "pac-parse.js");
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
  const orig = fs.readFileSync(path.join(SAMPLES, "orig.pac"), "utf8");

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
  assert(api.matchPacHost("rutor.info", lists), "rutor.info not packed");
  assert(api.matchPacHost("www.rutor.info", lists), "www.rutor.info not packed");
  assert(api.matchPacHost("rutracker.org", lists), "rutracker.org not packed");
  assert(api.matchPacHost("instagram.com", lists), "instagram.com not packed");
  assert(api.matchPacHost("x.com", lists), "x.com not packed");
  assert(!api.matchPacHost("example.com", lists), "example.com should not match packed");
  assert(lists.ips.includes("1.179.201.18"), "expected decoded IP missing");

  const html = "<!DOCTYPE html><html><body>IPFS Service Worker Gateway</body></html>";
  assert(api.isHtmlDocument(html), "HTML gateway should be detected");
  let threw = false;
  try { api.parsePacToLists(html); } catch (e) { threw = /HTML/i.test(String(e.message)); }
  assert(threw, "HTML document must not parse as PAC");

  const tiny = 'function FindProxyForURL(url, host){ if(dnsDomainIs(host, "example.org")) return "PROXY 1:2"; return "DIRECT"; }';
  const tinyLists = api.parsePacToLists(tiny);
  assert(tinyLists.extra.includes("example.org"), "quoted domain missing from tiny PAC");
  assert(api.matchPacHost("example.org", tinyLists), "tiny PAC host should match extra");

  const code = fs.readFileSync(PAC_PARSE, "utf8");
  assert(!/\bnew Function\b/.test(code), "pac-parse must not use new Function");
  assert(!/\beval\s*\(/.test(code), "pac-parse must not use eval");
  ["pac-parse.js", "Chrome/pac-parse.js", "EdgeOpera/pac-parse.js"].forEach(function (rel) {
    assert(fs.readFileSync(path.join(ROOT, rel), "utf8") === code, rel + " drifted from FireFox/pac-parse.js");
  });

  console.log("ok");
}

run();
