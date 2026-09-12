#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const filePath = fs.existsSync(path.join(ROOT, "src", "common", "pac-parse.js"))
  ? path.join(ROOT, "src", "common", "pac-parse.js")
  : path.join(ROOT, "pac-parse.js");
const code = fs.readFileSync(filePath, "utf8");
const sandbox = { console, module: { exports: {} }, btoa, unescape, encodeURIComponent };
sandbox.exports = sandbox.module.exports;
vm.createContext(sandbox);
vm.runInContext(code, sandbox, { filename: "pac-parse.js" });
const api = sandbox.PacParse || sandbox.module.exports;
const proxyConfigPath = path.join(ROOT, "src", "common", "proxy-config.js");
const proxySandbox = { module: { exports: {} }, crypto: require("crypto").webcrypto };
proxySandbox.exports = proxySandbox.module.exports;
vm.createContext(proxySandbox);
vm.runInContext(fs.readFileSync(proxyConfigPath, "utf8"), proxySandbox, { filename: "proxy-config.js" });
const proxyApi = proxySandbox.module.exports;

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

const a = { host: "127.0.0.1", port: 2080, username: "u1", password: "p1" };
const b = { host: "127.0.0.1", port: 2080, username: "u2", password: "p2" };
const c = { host: "127.0.0.1", port: 2080, username: "u1", password: "p1", name: "Домашний", type: "http" };
assert(proxyApi.proxyKey(a) !== proxyApi.proxyKey(b), "same host/port with different login must not be a duplicate");
assert(proxyApi.proxyKey(a) !== proxyApi.proxyKey(c), "proxy type must affect duplicate key");
assert(proxyApi.proxyKey({ host: "127.0.0.1", port: 2080 }) !== proxyApi.proxyKey({ host: "127.0.0.1", port: 2080, username: "u", password: "p" }), "empty auth is not the same as filled auth");
assert(proxyApi.uniqueId() !== proxyApi.uniqueId(), "generated IDs must be unique");

console.log("test-proxy-info: ok");
