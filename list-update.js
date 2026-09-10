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

  function clipError(err) {
    var text = "";
    if (err && err.message) text = String(err.message);
    else if (typeof err === "string") text = err;
    text = String(text || "").trim();
    if (!text) text = "Ошибка обновления";
    return text.slice(0, 180);
  }

  function markFailure(list, err, now) {
    if (!list) return list;
    list.updateError = clipError(err);
    list.lastAttemptAt = Number(now) || 0;
    list.updateFailCount = failCount(list) + 1;
    return list;
  }

  function isDue(list, now) {
    if (!list || !list.url) return false;
    now = Number(now) || 0;
    var attempt = Number(list.lastAttemptAt) || 0;
    if (list.updateError && attempt) {
      return now - attempt >= retryDelayMs(list);
    }
    return now - (Number(list.updatedAt) || 0) >= intervalMs(list);
  }

  function nextCheckAt(list, now) {
    if (!list || !list.url) return 0;
    now = Number(now) || 0;
    var attempt = Number(list.lastAttemptAt) || 0;
    if (list.updateError && attempt) {
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
    markFailure: markFailure,
    isDue: isDue,
    nextCheckAt: nextCheckAt,
    soonestCheckAt: soonestCheckAt,
    alarmWhen: alarmWhen
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.ListUpdate = api;
})(typeof self !== "undefined" ? self : this);
