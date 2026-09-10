#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const code = fs.readFileSync(path.join(ROOT, "pac-parse.js"), "utf8");
const sandbox = { console, module: { exports: {} }, btoa, unescape, encodeURIComponent };
sandbox.exports = sandbox.module.exports;
vm.createContext(sandbox);
vm.runInContext(code, sandbox, { filename: "pac-parse.js" });
const api = sandbox.PacParse || sandbox.module.exports;

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const none = api.userProxyToFirefox({ type: "socks", host: "", port: 2080 });
assert(none.type === "direct", "empty host must be direct");

const socks = api.userProxyToFirefox({
  type: "socks",
  host: "127.0.0.1",
  port: 2080,
  username: "user",
  password: "secret"
});
assert(socks.type === "socks", "socks type");
assert(socks.host === "127.0.0.1", "socks host");
assert(socks.port === 2080, "socks port");
assert(socks.proxyDNS === true, "socks proxyDNS");
assert(socks.username === "user", "socks username must be passed to Firefox");
assert(socks.password === "secret", "socks password must be passed to Firefox");

const socksNoAuth = api.userProxyToFirefox({ type: "socks", host: "127.0.0.1", port: 2080 });
assert(socksNoAuth.username == null && socksNoAuth.password == null, "omit empty socks auth");

const http = api.userProxyToFirefox({
  type: "http",
  host: "127.0.0.1",
  port: 2080,
  username: "user",
  password: "secret"
});
assert(http.type === "http", "http type");
assert(http.username == null && http.password == null, "http must not set socks username fields");
assert(http.proxyAuthorizationHeader === "Basic " + btoa("user:secret"), "http basic header");

function proxyKey(p) {
  const host = String(p.host || "").trim().toLowerCase();
  const port = Number(p.port) || 0;
  const user = String(p.username || "");
  const pass = String(p.password || "");
  return `${host}|${port}|${user}|${pass}`;
}

const a = { host: "127.0.0.1", port: 2080, username: "u1", password: "p1" };
const b = { host: "127.0.0.1", port: 2080, username: "u2", password: "p2" };
const c = { host: "127.0.0.1", port: 2080, username: "u1", password: "p1", name: "Домашний", type: "http" };
assert(proxyKey(a) !== proxyKey(b), "same host/port with different login must not be a duplicate");
assert(proxyKey(a) === proxyKey(c), "name and type must not affect duplicate key");
assert(proxyKey({ host: "127.0.0.1", port: 2080 }) !== proxyKey({ host: "127.0.0.1", port: 2080, username: "u", password: "p" }), "empty auth is not the same as filled auth");

console.log("test-proxy-info: ok");
