const browser = globalThis.browser || globalThis.chrome;

document.addEventListener("DOMContentLoaded", async () => {
  const proxyEditor = document.getElementById("proxyEditor");
  const directEditor = document.getElementById("directEditor");
  const saveBtn = document.getElementById("saveBtn");
  const status = document.getElementById("status");

  function isIpHost(h) {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || String(h || "").indexOf(":") >= 0;
  }
  function isAcceptableHost(h) {
    h = String(h || "");
    if (!h || /\s/.test(h) || /[^\x00-\x7F]/.test(h)) return false;
    if (isIpHost(h)) return true;
    if (!/^[a-z0-9.:\[\]-]+$/i.test(h)) return false;
    return h.indexOf(".") >= 0 && h.indexOf("..") < 0;
  }
  function normalizeRule(rule) {
    const trimmed = String(rule || "").trim();
    if (!trimmed || /\s/.test(trimmed)) return "";
    let s = trimmed.toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (/\s/.test(s)) return "";
    const wild = s.startsWith("*.");
    if (wild) s = s.slice(2);
    s = s.replace(/^\.+|\.+$/g, "");
    if (!s || !isAcceptableHost(s)) return "";
    if (isIpHost(s)) return s;
    return wild ? "*." + s : s;
  }
  function parseRules(text) { return [...new Set(String(text || "").split("\n").map(normalizeRule).filter(Boolean))]; }
  function dropOverlap(proxy, direct) {
    const d = new Set(direct.map(normalizeRule));
    return proxy.filter(r => !d.has(normalizeRule(r)));
  }
  function flash(text, color = "#57f287") { status.style.color = color; status.textContent = text; setTimeout(() => { if (status.textContent === text) status.textContent = ""; }, 1800); }

  const res = await browser.storage.local.get(["proxyRules", "directRules"]);
  const direct = Array.isArray(res.directRules) ? res.directRules : [];
  const proxy = dropOverlap(Array.isArray(res.proxyRules) ? res.proxyRules : [], direct);
  proxyEditor.value = proxy.join("\n");
  directEditor.value = direct.join("\n");

  saveBtn.addEventListener("click", async () => {
    const nextDirect = parseRules(directEditor.value);
    const nextProxy = dropOverlap(parseRules(proxyEditor.value), nextDirect);
    await browser.storage.local.set({ proxyRules: nextProxy, directRules: nextDirect });
    proxyEditor.value = nextProxy.join("\n");
    directEditor.value = nextDirect.join("\n");
    flash("Сохранено");
  });

  window.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
      e.preventDefault();
      saveBtn.click();
    }
  });
});

