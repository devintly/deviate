#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");

function resolveSrc(file) {
  const common = path.join(ROOT, "src", "common", file);
  if (fs.existsSync(common)) return common;
  return path.join(ROOT, file);
}

function load(file, sandbox) {
  vm.runInContext(fs.readFileSync(resolveSrc(file), "utf8"), sandbox, { filename: file });
}

const sandbox = { console, module: { exports: {} }, self: {} };
sandbox.exports = sandbox.module.exports;
vm.createContext(sandbox);
load("pac-parse.js", sandbox);
load("list-ingest.js", sandbox);
const api = sandbox.ListIngest || sandbox.self.ListIngest || sandbox.module.exports;

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

assert(api.isPacUrl("https://x.test/proxy.pac"), "pac url");
assert(!api.isPacUrl("https://x.test/list.txt"), "txt url");

const domains = api.parseList("example.com\n# skip\nsub.example.org\n0.0.0.0 ads.test");
assert(domains.includes("example.com"), "plain domain");
assert(domains.includes("sub.example.org"), "plain host");
assert(domains.includes("ads.test"), "hosts file");

const txt = api.ingestRemote("https://x.test/list.txt", "ok.example\n");
assert(txt.format === "txt", "txt ingest");
assert(txt.domains.includes("ok.example"), "txt domain");

let htmlErr = "";
try { api.ingestRemote("https://x.test/list.pac", "<!DOCTYPE html><html><body>IPFS</body></html>"); }
catch (e) { htmlErr = e.message; }
assert(/HTML/i.test(htmlErr), "html rejected");

console.log("test-list-ingest: ok");
