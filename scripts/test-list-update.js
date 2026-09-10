#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const code = fs.readFileSync(path.join(ROOT, "list-update.js"), "utf8");
const sandbox = { console, module: { exports: {} }, self: {} };
sandbox.exports = sandbox.module.exports;
vm.createContext(sandbox);
vm.runInContext(code, sandbox, { filename: "list-update.js" });
const api = sandbox.ListUpdate || sandbox.module.exports;

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const HOUR = 3600000;
const MIN = 60 * 1000;
const now = Date.parse("2026-09-10T14:07:00Z");

assert(api.intervalHours({}) === 12, "default interval");
assert(api.intervalHours({ intervalHours: 0 }) === 12, "zero interval falls back");
assert(api.intervalHours({ intervalHours: 200 }) === 168, "interval capped at 168");
assert(api.intervalMs({ intervalHours: 1 }) === HOUR, "1 hour in ms");
assert(api.RETRY_MS === 10 * MIN, "retry is 10 minutes");
assert(api.RETRY_LIMIT === 6, "six retry iterations");

assert(!api.isDue({ url: "" }, now), "no url is never due");
assert(api.isDue({ url: "https://example/list.txt" }, now), "never updated is due");
assert(!api.isDue({ url: "https://example/list.txt", updatedAt: now - HOUR, intervalHours: 12 }, now), "fresh list is not due");
assert(api.isDue({ url: "https://example/list.txt", updatedAt: now - 12 * HOUR, intervalHours: 12 }, now), "exactly at interval is due");
assert(api.isDue({ url: "https://example/list.txt", updatedAt: now - 12 * HOUR - 1, intervalHours: 12 }, now), "past interval is due");

const failed = {
  url: "https://example/list.txt",
  updatedAt: now - 13 * HOUR,
  intervalHours: 12,
  updateError: "HTTP 502",
  lastAttemptAt: now - 5 * MIN,
  updateFailCount: 1
};
assert(!api.isDue(failed, now), "failed list waits 10 minutes");
assert(api.isDue(failed, now + 5 * MIN), "failed list retries after 10 min");
assert(api.nextCheckAt(failed, now) === failed.lastAttemptAt + api.RETRY_MS, "next check is 10-min retry");
assert(api.retryDelayMs(failed) === api.RETRY_MS, "first failures use 10-min delay");

let burst = { url: "https://example/list.txt", intervalHours: 12, updatedAt: now - 13 * HOUR };
for (let i = 1; i <= 6; i++) {
  api.markFailure(burst, "HTTP 502", now + (i - 1) * api.RETRY_MS);
  assert(burst.updateFailCount === i, "fail count " + i);
  assert(api.retryDelayMs(burst) === api.RETRY_MS, "attempt " + i + " still retries in 10 min");
  assert(api.nextCheckAt(burst, now + (i - 1) * api.RETRY_MS) === now + i * api.RETRY_MS, "retry " + i + " in 10 min");
}
assert(api.isDue(burst, now + 6 * api.RETRY_MS), "sixth retry is due after an hour");
api.markFailure(burst, "HTTP 502", now + 6 * api.RETRY_MS);
assert(burst.updateFailCount === 7, "hour of retries exhausted");
assert(api.retryDelayMs(burst) === 12 * HOUR, "after 6 retries wait the configured interval");
assert(!api.isDue(burst, now + 6 * api.RETRY_MS + HOUR), "not due an hour after the burst");
assert(api.isDue(burst, now + 6 * api.RETRY_MS + 12 * HOUR), "due again at the configured interval");
assert(api.nextCheckAt(burst, now + 6 * api.RETRY_MS) === now + 6 * api.RETRY_MS + 12 * HOUR, "next check after burst is last attempt + interval");

const ok = { url: "https://example/list.txt", updatedAt: now - HOUR, intervalHours: 12 };
assert(api.nextCheckAt(ok, now) === ok.updatedAt + 12 * HOUR, "next check is last success + interval");
assert(api.alarmWhen([ok], now) === ok.updatedAt + 12 * HOUR, "alarm matches interval, not clock hour");

const overdue = { url: "https://example/list.txt", updatedAt: now - 20 * HOUR, intervalHours: 12 };
assert(api.alarmWhen([overdue], now) === now + api.MIN_ALARM_MS, "overdue alarm is at least 1 minute later");
assert(api.alarmWhen([], now) === 0, "no lists — no alarm");
assert(api.soonestCheckAt([ok, overdue], now) === now, "soonest is the overdue list");

assert(api.clipError(new Error("x".repeat(200))).length === 180, "error clipped");
assert(api.clipError({}) === "Ошибка обновления", "empty error fallback");
assert(api.clipError("HTTP 502") === "HTTP 502", "string error kept");

console.log("test-list-update: ok");
