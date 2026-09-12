(function (root) {
  "use strict";

  function isPacUrl(url) {
    try { return /\.(pac|dat)$/i.test(new URL(url).pathname); }
    catch (e) { return /\.pac(\?|#|$)/i.test(String(url || "")); }
  }

  function parseList(text) {
    var domains = {};
    var lines = String(text || "").split("\n");
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim().toLowerCase();
      var commentIdx = line.search(/\s+[#!]/);
      if (commentIdx >= 0) line = line.slice(0, commentIdx).trim();
      if (!line || line.charAt(0) === "!" || line.charAt(0) === "#") continue;
      var matchHosts = line.match(/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s]+)/);
      if (matchHosts) { domains[matchHosts[1]] = 1; continue; }
      if (/^(?:\*\.)?([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i.test(line)) {
        domains[line.replace(/^\*\./, "")] = 1;
      }
    }
    return Object.keys(domains);
  }

  function fail(code, text) {
    var err = new Error(text || code);
    err.code = code;
    return err;
  }

  function uniqueId() {
    try {
      if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
    } catch (e) {}
    return Date.now().toString(36) + "-" + Math.random().toString(36).slice(2);
  }

  function getPacParse() {
    if (typeof PacParse !== "undefined") return PacParse;
    if (root && root.PacParse) return root.PacParse;
    if (typeof globalThis !== "undefined" && globalThis.PacParse) return globalThis.PacParse;
    return null;
  }

  function ingestRemote(url, text) {
    var PacParse = getPacParse();
    if (PacParse && PacParse.isHtmlDocument(text)) {
      throw fail("error_html_response");
    }
    if (PacParse && PacParse.isPacText(text)) {
      var lists = PacParse.parsePacToLists(text);
      return {
        id: uniqueId(),
        url: url,
        type: "proxy",
        format: "pac",
        packed: lists.packed,
        patterns: lists.patterns,
        threePart: lists.threePart,
        extra: lists.extra,
        domains: lists.extra,
        ips: lists.ips,
        cidrs: lists.cidrs,
        domainCount: lists.domainCount,
        ipCount: lists.ipCount
      };
    }
    var domains = parseList(text);
    if (isPacUrl(url) && domains.length === 0) {
      throw fail(String(text || "").trim() ? "error_not_pac" : "error_empty_pac");
    }
    return {
      id: uniqueId(),
      url: url,
      type: "proxy",
      format: "txt",
      domains: domains,
      ips: [],
      cidrs: [],
      domainCount: domains.length,
      ipCount: 0
    };
  }

  function ingestRemoteAsync(url, text, workerUrl) {
    if (!workerUrl || typeof Worker === "undefined") {
      return Promise.resolve(ingestRemote(url, text));
    }
    return new Promise(function (resolve, reject) {
      var worker;
      try {
        worker = new Worker(workerUrl);
      } catch (e) {
        try { resolve(ingestRemote(url, text)); }
        catch (err) { reject(err); }
        return;
      }
      var timer = setTimeout(function () {
        try { worker.terminate(); } catch (e) {}
        reject(fail("error_parse_timeout"));
      }, 60000);
      var finish = function (fn) {
        clearTimeout(timer);
        try { worker.terminate(); } catch (e) {}
        fn();
      };
      worker.onmessage = function (e) {
        var data = e.data || {};
        if (data.ok) finish(function () { resolve(data.item); });
        else finish(function () { reject(fail(data.code || "error_parse", data.error)); });
      };
      worker.onerror = function (e) {
        finish(function () { reject(fail("error_parse", e && e.message)); });
      };
      try {
        worker.postMessage({ url: url, text: text });
      } catch (e) {
        finish(function () {
          try { resolve(ingestRemote(url, text)); }
          catch (err) { reject(err); }
        });
      }
    });
  }

  var api = { isPacUrl: isPacUrl, parseList: parseList, ingestRemote: ingestRemote, ingestRemoteAsync: ingestRemoteAsync };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.ListIngest = api;
})(typeof self !== "undefined" ? self : this);
