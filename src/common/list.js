const browser = globalThis.browser || globalThis.chrome;

document.addEventListener("DOMContentLoaded", async () => {
  if (typeof I18n !== "undefined") await I18n.init(browser);
  const saveBtn = document.getElementById("saveBtn");
  const status = document.getElementById("status");

  function parseRules(text) {
    const rules = [];
    const invalid = [];
    String(text || "").replace(/\r\n/g, "\n").split("\n").forEach((line, index) => {
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
    setTimeout(() => { if (status.textContent === text) status.textContent = ""; }, 2500);
  }

  function createEditor(textareaId, gutterId, backdropId, containerId) {
    const textarea = document.getElementById(textareaId);
    const gutter = document.getElementById(gutterId);
    const backdrop = document.getElementById(backdropId);
    const container = document.getElementById(containerId);
    let invalidSet = new Set();
    let rafId = null;

    function renderLines() {
      const lines = textarea.value.replace(/\r\n/g, "\n").split("\n");
      const count = Math.max(lines.length, 1);
      const gutterFrag = document.createDocumentFragment();
      const backdropFrag = document.createDocumentFragment();

      for (let i = 0; i < count; i++) {
        const lineNum = i + 1;
        const isInvalid = invalidSet.has(lineNum);
        
        const gDiv = document.createElement("div");
        gDiv.className = `gutter-line${isInvalid ? " invalid" : ""}`;
        gDiv.textContent = String(lineNum);
        gutterFrag.appendChild(gDiv);

        const bDiv = document.createElement("div");
        bDiv.className = `hl-line${isInvalid ? " invalid" : ""}`;
        backdropFrag.appendChild(bDiv);
      }

      gutter.textContent = "";
      gutter.appendChild(gutterFrag);
      backdrop.textContent = "";
      backdrop.appendChild(backdropFrag);
      container.classList.toggle("has-error", invalidSet.size > 0);
      syncScroll();
    }

    function syncScroll() {
      backdrop.scrollTop = textarea.scrollTop;
      backdrop.scrollLeft = textarea.scrollLeft;
      gutter.scrollTop = textarea.scrollTop;
    }

    function setInvalidLines(lineNumbers) {
      invalidSet = new Set(lineNumbers);
      renderLines();
    }

    function validate() {
      const parsed = parseRules(textarea.value);
      setInvalidLines(parsed.invalid);
      return parsed;
    }

    textarea.addEventListener("input", () => {
      if (rafId) cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(() => {
        validate();
      });
    });

    textarea.addEventListener("scroll", syncScroll, { passive: true });

    return {
      textarea,
      validate,
      renderLines,
      setInvalidLines,
      syncScroll
    };
  }

  const proxyEditor = createEditor("proxyEditor", "proxyGutter", "proxyBackdrop", "proxyContainer");
  const directEditor = createEditor("directEditor", "directGutter", "directBackdrop", "directContainer");

  const res = await browser.storage.local.get(["proxyRules", "directRules"]);
  const direct = Array.isArray(res.directRules) ? res.directRules : [];
  const proxy = dropOverlap(Array.isArray(res.proxyRules) ? res.proxyRules : [], direct);
  proxyEditor.textarea.value = proxy.join("\n");
  directEditor.textarea.value = direct.join("\n");
  proxyEditor.renderLines();
  directEditor.renderLines();

  window.addEventListener("resize", () => {
    proxyEditor.syncScroll();
    directEditor.syncScroll();
  });

  saveBtn.addEventListener("click", async () => {
    const directParsed = directEditor.validate();
    const proxyParsed = proxyEditor.validate();
    const invalid = directParsed.invalid.concat(proxyParsed.invalid);
    if (invalid.length) {
      flash(I18n.t("msg_invalid_rules", { lines: invalid.join(", ") }), true);
      return;
    }
    const nextDirect = directParsed.rules;
    const nextProxy = dropOverlap(proxyParsed.rules, nextDirect);
    await browser.storage.local.set({ proxyRules: nextProxy, directRules: nextDirect });
    proxyEditor.textarea.value = nextProxy.join("\n");
    directEditor.textarea.value = nextDirect.join("\n");
    proxyEditor.renderLines();
    directEditor.renderLines();
    flash(typeof I18n !== "undefined" ? I18n.t("list_editor_saved") : "Сохранено");
  });

  window.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
      e.preventDefault();
      saveBtn.click();
    }
  });
});
