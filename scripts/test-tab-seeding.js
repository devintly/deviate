#!/usr/bin/env node
"use strict";

const path = require("path");
const assert = (condition, message) => { if (!condition) throw new Error(message); };

const HostRules = require("../src/common/host-rules");
const ProxyConfig = require("../src/common/proxy-config");

const maps = HostRules.rebuildMaps(["*.rutracker.org", "instagram.com"], [], []);

const tabHosts = {};
const tabProxied = {};

const tabApex = {};

function isHostProxied(host) {
  return HostRules.hostIsProxied(host, true, maps);
}

function recordTabHost(tabId, host) {
  if (tabId == null || tabId < 0 || !host) return;
  const canon = HostRules.canonHost(host);
  if (!canon) return;
  const stored = HostRules.rememberHost(tabHosts, tabId, canon);
  if (!stored) return;
  if (isHostProxied(stored)) {
    if (!tabProxied[tabId]) tabProxied[tabId] = new Set();
    tabProxied[tabId].add(stored);
  }
}

function seedTabUrl(tabId, url) {
  if (tabId == null || tabId < 0 || !url || HostRules.isOwnPage(url, "chrome-extension://test/")) return;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return;
    const host = parsed.hostname.toLowerCase();
    if (host && !tabApex[tabId]) tabApex[tabId] = HostRules.apexDomain(host);
    recordTabHost(tabId, host);
  } catch (_) {}
}

function simulateNavigation(tabId, url, subrequests) {
  // Navigation starts: status loading with apex preservation
  const host = new URL(url).hostname.toLowerCase();
  const apex = HostRules.apexDomain(host);
  if (apex && tabApex[tabId] && apex !== tabApex[tabId]) {
    tabHosts[tabId] = new Set();
    tabProxied[tabId] = new Set();
  } else if (!tabHosts[tabId]) {
    tabHosts[tabId] = new Set();
    tabProxied[tabId] = new Set();
  }
  if (apex) tabApex[tabId] = apex;
  seedTabUrl(tabId, url);

  // Subrequests load
  (subrequests || []).forEach(sub => {
    try {
      const u = new URL(sub);
      recordTabHost(tabId, u.hostname);
    } catch (_) {}
  });

  // Navigation completes
  seedTabUrl(tabId, url);
}

// Case 1: Plain navigation with no subrequests
simulateNavigation(1, "https://rutracker.org/forum/index.php", []);
assert(tabHosts[1].has("rutracker.org"), "Main domain must be in tabHosts");
assert(tabProxied[1].has("rutracker.org"), "Main domain must be in tabProxied");
assert(tabProxied[1].size === 1, "Tab proxied count must be 1 for main domain alone");
assert(ProxyConfig.badgeText(tabProxied[1].size) === "1", "Badge text must be '1'");

// Case 2: Navigation with multiple subrequests (main domain + 2 proxied subdomains)
simulateNavigation(2, "https://rutracker.org/", [
  "https://static.rutracker.org/logo.png",
  "https://api.rutracker.org/v1/ping",
  "https://google-analytics.com/collect"
]);
assert(tabHosts[2].has("rutracker.org"), "Main domain must be present");
assert(tabHosts[2].has("static.rutracker.org"), "Subdomain static must be present");
assert(tabHosts[2].has("api.rutracker.org"), "Subdomain api must be present");
assert(tabHosts[2].has("google-analytics.com"), "Direct host must be in tabHosts");
assert(tabProxied[2].has("rutracker.org"), "Main domain must be counted in tabProxied");
assert(tabProxied[2].has("static.rutracker.org"), "Subdomain static must be in tabProxied");
assert(tabProxied[2].has("api.rutracker.org"), "Subdomain api must be in tabProxied");
assert(!tabProxied[2].has("google-analytics.com"), "Direct host must not be in tabProxied");
assert(tabProxied[2].size === 3, "Total proxied count must be 3 (main domain + 2 subdomains)");
assert(ProxyConfig.badgeText(tabProxied[2].size) === "3", "Badge text must be '3'");

// Case 4: Soft reload / background iframe reload on the SAME domain (rutracker.org)
// All previously captured subdomains MUST remain and not disappear!
simulateNavigation(2, "https://rutracker.org/forum/viewtopic.php?t=999", []);
assert(tabHosts[2].has("static.rutracker.org"), "Subdomain static must NOT disappear on same-site navigation");
assert(tabHosts[2].has("api.rutracker.org"), "Subdomain api must NOT disappear on same-site navigation");
assert(tabProxied[2].size === 3, "Total proxied count must remain 3 after same-site navigation");

// Case 5: Navigating to a DIFFERENT domain (from rutracker to wikipedia)
// Old subdomains MUST be cleared!
simulateNavigation(2, "https://wikipedia.org/", []);
assert(!tabHosts[2].has("static.rutracker.org"), "Old site subdomains must be cleared on cross-domain navigation");
assert(!tabHosts[2].has("rutracker.org"), "Old site main domain must be cleared on cross-domain navigation");
assert(tabHosts[2].has("wikipedia.org"), "New domain must be present");
assert(tabProxied[2].size === 0, "Direct new domain must have 0 proxied hosts");

console.log("test-tab-seeding: ok");
