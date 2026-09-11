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

  function ingestRemote(url, text) {
    var PacParse = root.PacParse;
    if (PacParse.isHtmlDocument(text)) {
      throw new Error("Сервер отдал HTML-страницу (часто IPFS-шлюз), а не PAC. Не сохраняйте файл через «Сохранить как» — добавьте URL списка в расширение, оно скачает PAC само.");
    }
    if (PacParse.isPacText(text)) {
      var lists = PacParse.parsePacToLists(text);
      return {
        id: Date.now(),
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
      var preview = String(text || "").replace(/\s+/g, " ").trim().slice(0, 180);
      throw new Error(preview ? "Ответ не похож на PAC-файл: " + preview : "Пустой ответ вместо PAC-файла");
    }
    return {
      id: Date.now(),
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

  var api = { isPacUrl: isPacUrl, parseList: parseList, ingestRemote: ingestRemote };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.ListIngest = api;
})(typeof self !== "undefined" ? self : this);
