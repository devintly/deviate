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

// 1. Basic 3rd level subdomains
{
  const hosts = ["google.com", "mail.google.com", "drive.google.com"];
  const tree = api.buildDomainTree(hosts, "google.com");
  assert(tree.length === 2, "2 roots under google.com");
  assert(tree[0].host === "drive.google.com" && tree[0].children.length === 0, "drive is leaf");
  assert(tree[1].host === "mail.google.com" && tree[1].children.length === 0, "mail is leaf");
}

// 2. Recursive 4th and 5th level nesting
{
  const hosts = [
    "google.com",
    "clients6.google.com",
    "ogads-pa.clients6.google.com",
    "sub.ogads-pa.clients6.google.com",
    "apis.google.com"
  ];
  const tree = api.buildDomainTree(hosts, "google.com");
  assert(tree.length === 2, "2 roots: apis and clients6");
  assert(tree[0].host === "apis.google.com" && tree[0].children.length === 0, "apis has no children");
  assert(tree[1].host === "clients6.google.com" && tree[1].children.length === 1, "clients6 has 1 child");

  const child4 = tree[1].children[0];
  assert(child4.host === "ogads-pa.clients6.google.com" && child4.children.length === 1, "ogads-pa has 1 child");

  const child5 = child4.children[0];
  assert(child5.host === "sub.ogads-pa.clients6.google.com" && child5.children.length === 0, "5th level is leaf");
}

// 3. Multiple sibling 4th level subdomains under a 3rd level
{
  const hosts = [
    "clients6.google.com",
    "beta.clients6.google.com",
    "alpha.clients6.google.com"
  ];
  const tree = api.buildDomainTree(hosts, "google.com");
  assert(tree.length === 1, "1 root: clients6");
  assert(tree[0].children.length === 2, "2 children under clients6");
  assert(tree[0].children[0].host === "alpha.clients6.google.com", "alpha sorted first");
  assert(tree[0].children[1].host === "beta.clients6.google.com", "beta sorted second");
}

// 4. Intermediate parents synthesized between apex and deep subdomains
{
  const hosts = ["deep.missing.google.com"];
  const tree = api.buildDomainTree(hosts, "google.com");
  assert(tree.length === 1, "1 root: missing.google.com");
  assert(tree[0].host === "missing.google.com", "missing.google.com is intermediate parent");
  assert(tree[0].children.length === 1 && tree[0].children[0].host === "deep.missing.google.com", "deep.missing is child");
}

// 6. User screenshot scenario: ogads-pa and waa-pa under clients6.google.com
{
  const hosts = [
    "google.com",
    "accounts.google.com",
    "ogads-pa.clients6.google.com",
    "ogs.google.com",
    "play.google.com",
    "waa-pa.clients6.google.com",
    "www.google.com"
  ];
  const tree = api.buildDomainTree(hosts, "google.com");
  assert(tree[0].host === "www.google.com", "www.google.com is first in 3rd level list");
  assert(tree.map(t => t.host).join(",") === "www.google.com,accounts.google.com,clients6.google.com,ogs.google.com,play.google.com", "other 3rd level subdomains sorted alphabetically after www.");
  const clients6 = tree.find(t => t.host === "clients6.google.com");
  assert(clients6, "clients6.google.com synthesized as 3rd-level parent");
  assert(clients6.children.length === 2, "clients6 has 2 children of 4th level");
  assert(clients6.children[0].host === "ogads-pa.clients6.google.com", "ogads-pa is child");
  assert(clients6.children[1].host === "waa-pa.clients6.google.com", "waa-pa is child");
}

// 5. Edge cases: empty, null, apex duplicates with different cases
{
  assert(api.buildDomainTree([], "google.com").length === 0, "empty list returns empty tree");
  assert(api.buildDomainTree(null, "google.com").length === 0, "null list returns empty tree");
  const dupes = ["Google.COM", "google.com", "sub.google.com", "SUB.google.com"];
  const tree = api.buildDomainTree(dupes, "google.com");
  assert(tree.length === 1, "deduplicated to 1 root");
  assert(tree[0].host === "sub.google.com", "sub.google.com normalized lowercase");
}

console.log("test-domain-tree: ok");
