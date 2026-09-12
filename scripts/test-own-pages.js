#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const code = fs.readFileSync(path.join(ROOT, "src", "common", "host-rules.js"), "utf8");
const sandbox = { console, module: { exports: {} }, self: {}, URL };
sandbox.exports = sandbox.module.exports;
vm.createContext(sandbox);
vm.runInContext(code, sandbox, { filename: "host-rules.js" });
const api = sandbox.HostRules || sandbox.self.HostRules || sandbox.module.exports;

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const self = "moz-extension://abc-123/";
assert(api.isOwnPage("moz-extension://abc-123/popup.html", self), "settings tab");
assert(api.isOwnPage("moz-extension://abc-123/list.html", self), "rules editor tab");
assert(!api.isOwnPage("https://rutor.info/", self), "regular site");
assert(!api.isOwnPage("moz-extension://other-ext/popup.html", self), "other extension");
assert(!api.isOwnPage("", self), "empty");
assert(api.isOwnPage("moz-extension://abc-123/popup.html#foo", self), "settings hash");

assert(!api.isWebTab({ url: "moz-extension://abc-123/list.html" }, self), "own page is not a web tab");
assert(api.isWebTab({ url: "https://rutor.info/" }, self), "web tab kept");
assert(!api.isWebTab({ url: "about:blank" }, self), "about blank");

console.log("test-own-pages: ok");
