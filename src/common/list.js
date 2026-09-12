const browser = globalThis.browser || globalThis.chrome;

document.addEventListener("DOMContentLoaded", async () => {
  if (typeof I18n !== "undefined") await I18n.init(browser);
  const proxyEditor = document.getElementById("proxyEditor");
  const directEditor = document.getElementById("directEditor");
  const saveBtn = document.getElementById("saveBtn");
  const status = document.getElementById("status");

  function parseRules(text) {
    const rules = [];
    const invalid = [];
    String(text || "").split("\n").forEach((line, index) => {
      const raw = line.trim();
      if (!raw) return;
      const normalized = HostRules.normalizeRule(raw);
      if (!normalized) invalid.push(index + 1);
      else if (!rules.includes(normalized)) rules.push(normalized);
    });
    return { rules, invalid };
  }
  function dropOverlap(proxy, direct) {
    const d = new Set(direct.map(HostRules.normalizeRule));
    return proxy.filter(r => !d.has(HostRules.normalizeRule(r)));
  }
  function flash(text, error) {
    status.style.color = error ? "#ff6b6b" : "#57f287";
    status.textContent = text;
    setTimeout(() => { if (status.textContent === text) status.textContent = ""; }, 1800);
  }

  const res = await browser.storage.local.get(["proxyRules", "directRules"]);
  const direct = Array.isArray(res.directRules) ? res.directRules : [];
  const proxy = dropOverlap(Array.isArray(res.proxyRules) ? res.proxyRules : [], direct);
  proxyEditor.value = proxy.join("\n");
  directEditor.value = direct.join("\n");

  saveBtn.addEventListener("click", async () => {
    const directParsed = parseRules(directEditor.value);
    const proxyParsed = parseRules(proxyEditor.value);
    const invalid = directParsed.invalid.concat(proxyParsed.invalid);
    if (invalid.length) {
      flash(I18n.t("msg_invalid_rules", { lines: invalid.join(", ") }), true);
      return;
    }
    const nextDirect = directParsed.rules;
    const nextProxy = dropOverlap(proxyParsed.rules, nextDirect);
    await browser.storage.local.set({ proxyRules: nextProxy, directRules: nextDirect });
    proxyEditor.value = nextProxy.join("\n");
    directEditor.value = nextDirect.join("\n");
    flash(typeof I18n !== "undefined" ? I18n.t("list_editor_saved") : "Сохранено");
  });

  window.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
      e.preventDefault();
      saveBtn.click();
    }
  });
});
