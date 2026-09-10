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

console.log("test-own-pages: ok");
