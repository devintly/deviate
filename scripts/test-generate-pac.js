#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const code = fs.readFileSync(path.join(ROOT, "src", "common", "generate-pac.js"), "utf8");
const sandbox = { console, module: { exports: {} }, self: {} };
sandbox.exports = sandbox.module.exports;
vm.createContext(sandbox);
vm.runInContext(code, sandbox, { filename: "generate-pac.js" });
const api = sandbox.GeneratePac || sandbox.self.GeneratePac || sandbox.module.exports;

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const pac = api.generatePacScript("SOCKS5 127.0.0.1:1080; DIRECT", {
  dE: { "direct.test": 1 },
  dS: {},
  dIp: {},
  pE: { "proxy.test": 1 },
  pS: { ".listed.example": 1 },
  pIp: { "1.2.3.4": 1 },
  pCidr: [],
  pPac: [],
  viaProxyHosts: { "cdn.example": 1 }
}, { 7: "SOCKS5 10.0.0.1:1080" });

assert(pac.includes("function matchMaps"), "PAC has unified matchMaps");
assert(pac.includes("split(patterns[token]).join(token)"), "PAC applyPatterns matches PacParse");
assert(!pac.includes("split(k).join(patterns[k])"), "PAC must not invert pattern replace");
assert(pac.includes("__deviate_probe="), "PAC keeps probe hook");
assert(pac.includes("cdn.example"), "viaProxy host serialized");

assert(pac.includes("extraList: p.extra ? Object.keys(p.extra) : []"), "PAC precomputes extraList");
assert(pac.includes("for (var e = 0; e < p.extraList.length; e++)"), "PAC matchPac iterates extraList without Object.keys");
assert(!pac.includes("var extraKeys = Object.keys(p.extra)"), "PAC hot loop does not allocate extraKeys");

const probe = api.generateProbePac({ 1: "PROXY 127.0.0.1:8080" });
assert(probe.includes("FindProxyForURL"), "probe PAC");
assert(probe.includes("PROXY 127.0.0.1:8080"), "probe proxy string");

console.log("test-generate-pac: ok");
