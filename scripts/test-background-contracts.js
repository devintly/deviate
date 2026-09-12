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

const manifest = JSON.parse(read("src/chrome/manifest.json"));
assert(manifest.permissions.includes("offscreen"), "Chrome offscreen permission missing");
assert(fs.existsSync(path.join(root, "src/chrome/offscreen.html")), "offscreen document missing");

console.log("test-background-contracts: ok");
