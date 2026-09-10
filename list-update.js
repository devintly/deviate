(function (root) {
  "use strict";

  var HOUR_MS = 3600000;
  var RETRY_MS = 30 * 60 * 1000;
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

  function clipError(err) {
    var text = "";
    if (err && err.message) text = String(err.message);
    else if (typeof err === "string") text = err;
    text = String(text || "").trim();
    if (!text) text = "Ошибка обновления";
    return text.slice(0, 180);
  }

  function isDue(list, now) {
    if (!list || !list.url) return false;
    now = Number(now) || 0;
    if (now - (Number(list.updatedAt) || 0) < intervalMs(list)) return false;
    if (list.updateError) {
      var attempt = Number(list.lastAttemptAt) || 0;
      if (attempt && now - attempt < RETRY_MS) return false;
    }
    return true;
  }

  function nextCheckAt(list, now) {
    if (!list || !list.url) return 0;
    now = Number(now) || 0;
    var due = (Number(list.updatedAt) || 0) + intervalMs(list);
    if (now < due) return due;
    if (list.updateError) {
      var retryAt = (Number(list.lastAttemptAt) || 0) + RETRY_MS;
      if (now < retryAt) return retryAt;
    }
    return now;
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
    MIN_ALARM_MS: MIN_ALARM_MS,
    DEFAULT_HOURS: DEFAULT_HOURS,
    MAX_HOURS: MAX_HOURS,
    intervalHours: intervalHours,
    intervalMs: intervalMs,
    clipError: clipError,
    isDue: isDue,
    nextCheckAt: nextCheckAt,
    soonestCheckAt: soonestCheckAt,
    alarmWhen: alarmWhen
  };

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.ListUpdate = api;
})(typeof self !== "undefined" ? self : this);
