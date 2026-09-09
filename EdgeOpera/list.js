const api = typeof browser !== "undefined" ? browser : chrome;

document.addEventListener("DOMContentLoaded", () => {
  const proxyEditor = document.getElementById("proxyEditor");
  const directEditor = document.getElementById("directEditor");
  const saveBtn = document.getElementById("saveBtn");
  const status = document.getElementById("status");

  function normalizeRule(rule) { return String(rule || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, ""); }
  function parseRules(text) { return [...new Set(String(text || "").split("\n").map(normalizeRule).filter(Boolean))]; }
  function dropOverlap(proxy, direct) {
    const d = new Set(direct.map(normalizeRule));
    return proxy.filter(r => !d.has(normalizeRule(r)));
  }
  function flash(text, color = "#57f287") { status.style.color = color; status.textContent = text; setTimeout(() => { if (status.textContent === text) status.textContent = ""; }, 1800); }

  api.storage.local.get(["proxyRules", "directRules"], (res) => {
    const direct = Array.isArray(res.directRules) ? res.directRules : [];
    const proxy = dropOverlap(Array.isArray(res.proxyRules) ? res.proxyRules : [], direct);
    proxyEditor.value = proxy.join("\n");
    directEditor.value = direct.join("\n");
  });

  saveBtn.addEventListener("click", () => {
    const nextDirect = parseRules(directEditor.value);
    const nextProxy = dropOverlap(parseRules(proxyEditor.value), nextDirect);
    api.storage.local.set({ proxyRules: nextProxy, directRules: nextDirect }, () => {
      proxyEditor.value = nextProxy.join("\n");
      directEditor.value = nextDirect.join("\n");
      flash("Сохранено");
    });
  });
});
