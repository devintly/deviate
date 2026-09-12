#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const root = path.join(__dirname, "..");
const read = file => fs.readFileSync(path.join(root, file), "utf8");
const assert = (condition, message) => { if (!condition) throw new Error(message); };

const chrome = read("src/chrome/background.js");
const firefox = read("src/firefox/background.js");
new vm.Script(chrome, { filename: "chrome/background.js" });
new vm.Script(firefox, { filename: "firefox/background.js" });

assert(/runtime\.lastError/.test(chrome), "Chrome proxy callbacks must inspect runtime.lastError");
assert(/offscreen\.createDocument/.test(chrome) && /target:\s*"offscreen"/.test(chrome), "Chrome must parse lists offscreen");
assert(/listUpdateQueue\.then/.test(chrome) && /listUpdateQueue\.then/.test(firefox), "list updates must be serialized");
assert(/initPromise\.then\(updateDueLists\)/.test(firefox), "Firefox alarms must await initialization");

assert(/function seedTabUrl\(/.test(chrome) && /function seedTabUrl\(/.test(firefox), "Both Chrome and Firefox must implement seedTabUrl");
assert(/pendingUrl/.test(chrome) && /pendingUrl/.test(firefox), "Both Chrome and Firefox must support pendingUrl in tabs.onUpdated");
assert(/ensureInit\(\)\.then/.test(chrome), "Chrome webRequest must await initialization before recording hosts");
assert(/sessionAvailable/.test(chrome), "Chrome must support session storage for tab hosts");

assert(/function getProxyStatus\(/.test(chrome), "Chrome background must implement getProxyStatus");
assert(/controlled_by_other_extensions/.test(chrome) && /controlled_by_other_extensions/.test(firefox), "Both Chrome and Firefox must check controlled_by_other_extensions");

const manifest = JSON.parse(read("src/chrome/manifest.json"));
assert(manifest.permissions.includes("offscreen"), "Chrome offscreen permission missing");
assert(fs.existsSync(path.join(root, "src/chrome/offscreen.html")), "offscreen document missing");

console.log("test-background-contracts: ok");
