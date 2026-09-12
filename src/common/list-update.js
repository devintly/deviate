(function (root) {
  "use strict";

  var HOUR_MS = 3600000;
  var RETRY_MS = 10 * 60 * 1000;
  var RETRY_LIMIT = 6;
  var MIN_ALARM_MS = 60 * 1000;
  var DEFAULT_HOURS = 12;
  var MAX_HOURS = 168;

  function intervalHours(list) {
    var hours = Number(list && list.intervalHours);
    if (!(hours > 0)) hours = DEFAULT_HOURS;
    if (hours > MAX_HOURS) hours = MAX_HOURS;
    return hours;
  }

  function intervalMs(list) {
    return intervalHours(list) * HOUR_MS;
  }

  function failCount(list) {
    var n = Number(list && list.updateFailCount) || 0;
    return n > 0 ? n : 0;
  }

  function retryDelayMs(list) {
    return failCount(list) <= RETRY_LIMIT ? RETRY_MS : intervalMs(list);
  }

  function codedError(code, text) {
    var err = new Error(String(text || code || "").trim());
    err.code = code || "";
    return err;
  }

  function clipError(err) {
    var text = "";
    if (err && err.message) text = String(err.message);
    else if (typeof err === "string") text = err;
    text = String(text || "").trim();
    if (!text) text = "Ошибка обновления";
    return text.slice(0, 180);
  }

  function errorCode(err) {
    if (err && err.code) return String(err.code);
    return "";
  }

  function hasUpdateError(list) {
    return !!(list && (list.updateError || list.updateErrorCode));
  }

  function markFailure(list, err, now) {
    if (!list) return list;
    list.updateError = clipError(err);
    list.updateErrorCode = errorCode(err);
    delete list.lastError;
    list.lastAttemptAt = Number(now) || 0;
    list.updateFailCount = failCount(list) + 1;
    return list;
  }

  function isDue(list, now) {
    if (!list || !list.url || list.enabled === false) return false;
    now = Number(now) || 0;
    var attempt = Number(list.lastAttemptAt) || 0;
    if (hasUpdateError(list) && attempt) {
      return now - attempt >= retryDelayMs(list);
    }
    return now - (Number(list.updatedAt) || 0) >= intervalMs(list);
  }

  function nextCheckAt(list, now) {
    if (!list || !list.url || list.enabled === false) return 0;
    now = Number(now) || 0;
    var attempt = Number(list.lastAttemptAt) || 0;
    if (hasUpdateError(list) && attempt) {
      var retryAt = attempt + retryDelayMs(list);
      return now < retryAt ? retryAt : now;
    }
    var due = (Number(list.updatedAt) || 0) + intervalMs(list);
    return now < due ? due : now;
  }

  function soonestCheckAt(lists, now) {
    var soonest = 0;
    (lists || []).forEach(function (list) {
      var at = nextCheckAt(list, now);
      if (!at) return;
      if (!soonest || at < soonest) soonest = at;
    });
    return soonest;
  }

  function alarmWhen(lists, now) {
    now = Number(now) || 0;
    var soonest = soonestCheckAt(lists, now);
    if (!soonest) return 0;
    return soonest < now + MIN_ALARM_MS ? now + MIN_ALARM_MS : soonest;
  }

  function fetchRouteOverride(host, tabId, directHosts, proxyHosts) {
    if (tabId >= 0) return "";
    host = String(host || "").toLowerCase();
    if (!host) return "";
    if (proxyHosts && (proxyHosts[host] || proxyHosts["*"])) return "proxy";
    if (directHosts && (directHosts[host] || directHosts["*"])) return "direct";
    return "";
  }

  function canonListUrl(url) {
    try {
      var parsed = new URL(String(url || "").trim());
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
      parsed.hash = "";
      if (parsed.pathname !== "/") parsed.pathname = parsed.pathname.replace(/\/+$/, "");
      return parsed.href;
    } catch (e) {
      return "";
    }
  }

  function validListUrl(url) {
    return !!canonListUrl(url);
  }

  function findListByUrl(lists, url, exceptId) {
    var c = canonListUrl(url);
    if (!c) return undefined;
    return (lists || []).find(function (l) {
      return l && canonListUrl(l.url) === c && (exceptId == null || l.id !== exceptId);
    });
  }

  function listMeta(src, current) {
    src = src || {};
    current = current || {};
    var name = String(src.name !== undefined ? src.name : (current.name || "")).trim();
    var hoursSrc = src.intervalHours !== undefined ? src.intervalHours : current.intervalHours;
    var viaProxy = !!(src.viaProxy !== undefined ? src.viaProxy : current.viaProxy);
    var enabled = src.enabled !== undefined ? src.enabled !== false
      : (current.enabled !== undefined ? current.enabled !== false : true);
    return { name: name, intervalHours: intervalHours({ intervalHours: hoursSrc }), viaProxy: viaProxy, enabled: enabled };
  }

  function commitFetchedList(lists, item, meta, url, existingId, now) {
    var next = Object.assign({}, item);
    delete next.pacScript;
    delete next.pacIndex;
    next.name = meta && meta.name != null ? String(meta.name) : (next.name || "");
    next.intervalHours = meta ? meta.intervalHours : next.intervalHours;
    next.viaProxy = !!(meta && meta.viaProxy);
    next.updatedAt = Number(now) || 0;
    next.updateError = "";
    next.updateErrorCode = "";
    delete next.lastError;
    next.updateFailCount = 0;
    next.lastAttemptAt = next.updatedAt;
    next.url = url;
    next.type = "proxy";
    var prevEnabled = true;
    if (existingId != null) {
      next.id = existingId;
      var idx = -1;
      for (var i = 0; i < lists.length; i++) {
        if (lists[i] && lists[i].id === existingId) { idx = i; break; }
      }
      if (idx >= 0) {
        prevEnabled = lists[idx].enabled !== false;
        lists[idx] = next;
      } else {
        lists.push(next);
      }
    } else {
      lists.push(next);
    }
    next.enabled = meta && meta.enabled !== undefined ? meta.enabled !== false : prevEnabled;
    return next;
  }

  function isStalePac(list) {
    if (!list || list.format !== "pac" || !list.url) return false;
    if (list.pacScript || list.pacIndex) return true;
    if (list.packed && (list.domainCount || 0) >= 100) return false;
    var domains = (list.domains && list.domains.length) || 0;
    var ips = (list.ips && list.ips.length) || 0;
    return (!domains && !ips) || (domains > 0 && domains < 100 && !ips);
  }

  function migrateList(list) {
    if (!list) return list;
    delete list.pacScript;
    delete list.pacIndex;
    if (!list.updateError && list.lastError) list.updateError = String(list.lastError);
    delete list.lastError;
    return list;
  }

  var api = {
    RETRY_MS: RETRY_MS,
    RETRY_LIMIT: RETRY_LIMIT,
    MIN_ALARM_MS: MIN_ALARM_MS,
    DEFAULT_HOURS: DEFAULT_HOURS,
    MAX_HOURS: MAX_HOURS,
    intervalHours: intervalHours,
    intervalMs: intervalMs,
    failCount: failCount,
    retryDelayMs: retryDelayMs,
    clipError: clipError,
    codedError: codedError,
    hasUpdateError: hasUpdateError,
    markFailure: markFailure,
    isDue: isDue,
    nextCheckAt: nextCheckAt,
    soonestCheckAt: soonestCheckAt,
    alarmWhen: alarmWhen,
    fetchRouteOverride: fetchRouteOverride,
    commitFetchedList: commitFetchedList,
    canonListUrl: canonListUrl,
    validListUrl: validListUrl,
    findListByUrl: findListByUrl,
    listMeta: listMeta,
    isStalePac: isStalePac,
    migrateList: migrateList
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.ListUpdate = api;
})(typeof self !== "undefined" ? self : this);
