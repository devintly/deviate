"use strict";
importScripts("pac-parse.js", "list-ingest.js");

self.onmessage = function (e) {
  var data = e.data || {};
  try {
    self.postMessage({ ok: true, item: ListIngest.ingestRemote(data.url, data.text) });
  } catch (err) {
    self.postMessage({ ok: false, error: String((err && err.message) || err) });
  }
};
