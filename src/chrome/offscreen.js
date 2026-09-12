"use strict";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.target !== "offscreen" || message.action !== "ingestList") return false;
  ListIngest.ingestRemoteAsync(
    message.url,
    message.text,
    chrome.runtime.getURL("list-ingest-worker.js")
  ).then(item => sendResponse({ success: true, item }))
    .catch(error => sendResponse({
      success: false,
      error: String((error && error.message) || error),
      code: (error && error.code) || ""
    }));
  return true;
});
