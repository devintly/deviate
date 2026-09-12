#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const common = path.join(__dirname, "..", "src", "common");
const sandbox = { module: { exports: {} }, self: {}, URL, Set };
sandbox.exports = sandbox.module.exports;
vm.createContext(sandbox);
for (const file of ["pac-parse.js", "host-rules.js", "generate-pac.js"]) {
  vm.runInContext(fs.readFileSync(path.join(common, file), "utf8"), sandbox, { filename: file });
}

const rules = ["example.com", "*.proxy.test"];
const direct = ["skip.proxy.test"];
const lists = [{ enabled: true, format: "txt", domains: ["listed.test"], ips: [], cidrs: [] }];
const hostRules = sandbox.self.HostRules;
const generatePac = sandbox.self.GeneratePac;
const maps = hostRules.rebuildMaps(rules, direct, lists);
const pac = { URL };
vm.createContext(pac);
vm.runInContext(generatePac.generatePacScript("PROXY 127.0.0.1:8080", maps, {}), pac);

for (const host of ["example.com", "www.example.com", "a.example.com", "proxy.test", "a.proxy.test", "skip.proxy.test", "listed.test", "a.listed.test", "other.test"]) {
  const expected = hostRules.hostIsProxied(host, true, maps, false);
  const actual = pac.FindProxyForURL("https://" + host + "/", host).startsWith("PROXY");
  if (actual !== expected) throw new Error(`routing mismatch for ${host}: PAC=${actual}, rules=${expected}`);
}

const ipMaps = hostRules.rebuildMaps(["1.2.3.4"], [], []);
const dnsPac = { dnsResolve: host => host === "resolved.test" ? "1.2.3.4" : "" };
vm.createContext(dnsPac);
vm.runInContext(generatePac.generatePacScript("PROXY 127.0.0.1:8080", ipMaps, {}), dnsPac);
if (!dnsPac.FindProxyForURL("https://resolved.test/", "resolved.test").startsWith("PROXY")) {
  throw new Error("PAC DNS-to-IP routing mismatch");
}

console.log("test-routing-parity: ok");
