#!/usr/bin/env node
"use strict";

function isOwnPage(url, selfBase) {
  const s = String(url || "");
  if (!s) return false;
  return !!(selfBase && s.indexOf(selfBase) === 0);
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const self = "moz-extension://abc-123/";
assert(isOwnPage("moz-extension://abc-123/popup.html", self), "settings tab");
assert(isOwnPage("moz-extension://abc-123/list.html", self), "rules editor tab");
assert(!isOwnPage("https://rutor.info/", self), "regular site");
assert(!isOwnPage("moz-extension://other-ext/popup.html", self), "other extension");
assert(!isOwnPage("", self), "empty");
assert(isOwnPage("moz-extension://abc-123/popup.html#foo", self), "settings hash");

function pickActiveTab(active, fallbackWeb) {
  if (active && !isOwnPage(active.url, self) && /^https?:/.test(active.url || "")) return active;
  return null;
}
assert(pickActiveTab({ url: "moz-extension://abc-123/list.html" }, { url: "https://rutor.info/" }) === null, "own page must not fall back to another site");
assert(pickActiveTab({ url: "https://rutor.info/" }) && pickActiveTab({ url: "https://rutor.info/" }).url === "https://rutor.info/", "web tab kept");

console.log("test-own-pages: ok");
