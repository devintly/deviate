document.addEventListener("DOMContentLoaded", async () => {
  const tabs = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".panel");
  const els = {
    domainInput: document.getElementById("domainInput"), statusIcon: document.getElementById("statusIcon"),
    toggleRule: document.getElementById("toggleRuleBtn"), viewDomains: document.getElementById("viewDomainsBtn"),
    domainsPanel: document.getElementById("domainsPanel"), domainsList: document.getElementById("domainsList"),
    domainsEmpty: document.getElementById("domainsEmpty"),
    rulesStatus: document.getElementById("rulesStatus"), openList: document.getElementById("openListBtn"),
    pType: document.getElementById("proxyType"), pHost: document.getElementById("proxyHost"),
    pPort: document.getElementById("proxyPort"), pUser: document.getElementById("proxyUser"),
    pPass: document.getElementById("proxyPass"), saveProxy: document.getElementById("saveProxyBtn"),
    pStatus: document.getElementById("proxyStatus"), lUrl: document.getElementById("listUrl"),
    lAct: document.getElementById("listAction"), addList: document.getElementById("addListBtn"),
    refreshLists: document.getElementById("refreshListsBtn"),
    toggleLists: document.getElementById("toggleListsBtn"), lCont: document.getElementById("listsContainer"),
    lStatus: document.getElementById("listStatus")
  };

  let currentRules = [];
  let currentLists = [];
  let activeTab = null;
  let domainsPanelOpen = false;
  const HOST_ORIGINS = ["http://*/*", "https://*/*", "ws://*/*", "wss://*/*"];
  const accessError = document.getElementById("accessError");
  const accessErrorText = document.getElementById("accessErrorText");

  async function refreshAccessErrors() {
    const msgs = [];
    try {
      if (browser.permissions && browser.permissions.contains) {
        const sites = await browser.permissions.contains({ origins: HOST_ORIGINS });
        if (!sites) msgs.push("Нет доступа к сайтам. Включите его в разрешениях расширения — без этого прокси по спискам не работает.");
      }
    } catch (e) {}
    if (accessError && accessErrorText) {
      accessErrorText.textContent = msgs.join("\n\n");
      accessError.style.display = msgs.length ? "block" : "none";
    }
  }

  if (browser.permissions && browser.permissions.onAdded) {
    browser.permissions.onAdded.addListener(refreshAccessErrors);
  }
  if (browser.permissions && browser.permissions.onRemoved) {
    browser.permissions.onRemoved.addListener(refreshAccessErrors);
  }

  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      panels.forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      panels[i].classList.add("active");
    });
  });

  els.toggleLists.addEventListener("click", () => {
    els.lCont.style.display = els.lCont.style.display === "none" ? "block" : "none";
  });

  function normalize(v) { return String(v||"").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, ""); }
  function toGuiRule(v) { const h = normalize(v).replace(/^\*\./, ""); return h ? `*.${h}` : ""; }
  function matches(h, r) {
    const hh = normalize(h), rr = normalize(r);
    if (!hh || !rr) return false;
    if (rr.startsWith("*.")) { const b = rr.slice(2); return hh === b || hh.endsWith(`.${b}`); }
    return hh === rr;
  }
  function hasUserRule(rule) {
    const n = normalize(rule);
    return !!n && currentRules.some(r => normalize(r) === n);
  }
  function refreshIcon() {
    const v = els.domainInput.value.trim();
    els.statusIcon.textContent = currentRules.some(r => matches(v, r)) ? "✅" : "❌";
    refreshToggleBtn();
  }
  function refreshToggleBtn() {
    const rule = toGuiRule(els.domainInput.value);
    const inList = hasUserRule(rule);
    els.toggleRule.textContent = inList ? "Удалить домен" : "Добавить домен";
    els.toggleRule.className = inList ? "danger" : "primary";
    els.toggleRule.disabled = !rule;
  }
  function flash(el, t, c = "#57f287") {
    el.style.color = c; el.textContent = t;
    setTimeout(() => { if (el.textContent === t) el.textContent = ""; }, 2000);
  }

  async function checkAutoReload(rule) {
    if (activeTab && activeTab.url) {
      const url = new URL(activeTab.url);
      if (matches(url.hostname, rule)) await browser.tabs.reload(activeTab.id);
    }
  }

  async function saveRules() {
    await browser.storage.local.set({ proxyRules: currentRules });
  }

  async function fetchTabDomains() {
    const set = new Set();
    if (activeTab && activeTab.url) {
      try {
        const host = new URL(activeTab.url).hostname;
        if (host) set.add(host.toLowerCase());
      } catch (_) {}
    }
    if (activeTab) {
      try {
        const res = await browser.runtime.sendMessage({ action: "getTabDomains", tabId: activeTab.id });
        (res && res.domains ? res.domains : []).forEach(d => {
          const h = String(d || "").trim().toLowerCase();
          if (h) set.add(h);
        });
      } catch (_) {}
    }
    return Array.from(set).sort();
  }

  function renderDomainsList(domains) {
    els.domainsList.textContent = "";
    if (!domains.length) {
      els.domainsEmpty.style.display = "block";
      return;
    }
    els.domainsEmpty.style.display = "none";
    domains.forEach(host => {
      const rule = toGuiRule(host);
      const row = document.createElement("label");
      row.className = "domain-check";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = hasUserRule(rule);
      const span = document.createElement("span");
      span.textContent = rule;
      span.title = host;
      row.appendChild(cb);
      row.appendChild(span);
      cb.addEventListener("change", async () => {
        if (cb.checked) {
          if (!hasUserRule(rule)) currentRules.push(rule);
        } else {
          currentRules = currentRules.filter(i => normalize(i) !== normalize(rule));
        }
        await saveRules();
        refreshIcon();
        checkAutoReload(rule);
      });
      els.domainsList.appendChild(row);
    });
  }

  async function refreshDomainsPanel() {
    if (!domainsPanelOpen) return;
    renderDomainsList(await fetchTabDomains());
  }

  function renderLists() {
    els.lCont.textContent = "";
    if (currentLists.length > 0) {
      els.toggleLists.style.display = "block";
      els.toggleLists.textContent = `Управление списками (${currentLists.length})`;
    } else {
      els.toggleLists.style.display = "none";
      els.lCont.style.display = "none";
    }

    currentLists.forEach(l => {
      const div = document.createElement("div"); div.className = "list-item";
      const infoDiv = document.createElement("div"); infoDiv.className = "info"; infoDiv.title = l.url;
      const isPac = l.format === "pac";
      const typ = l.type === "block" ? "🛑 Блок" : (isPac ? "📜 PAC" : "🚀 Прокси");
      const count = `${l.domainCount || (l.domains || []).length} дом. / ${l.ipCount || (l.ips || []).length} IP`;
      infoDiv.textContent = `[${typ}] ${count}`;
      infoDiv.appendChild(document.createElement("br"));
      const span = document.createElement("span"); span.style.color = "#b5bac1"; span.style.fontSize = "10px"; span.textContent = l.url;
      infoDiv.appendChild(span);
      const delDiv = document.createElement("div"); delDiv.className = "del"; delDiv.dataset.id = l.id; delDiv.textContent = "✖";
      div.appendChild(infoDiv); div.appendChild(delDiv); els.lCont.appendChild(div);
    });

    document.querySelectorAll(".del").forEach(btn => {
      btn.addEventListener("click", async (e) => {
        const id = Number(e.target.dataset.id);
        currentLists = currentLists.filter(x => x.id !== id);
        await browser.storage.local.set({ proxyLists: currentLists });
        renderLists();
      });
    });
  }

  async function loadState() {
    const res = await browser.storage.local.get(["proxyConfig", "proxyRules", "proxyLists", "lastProxyError"]);
    currentRules = Array.isArray(res.proxyRules) ? res.proxyRules : [];
    currentLists = Array.isArray(res.proxyLists) ? res.proxyLists : [];
    if (res.proxyConfig) {
      els.pType.value = res.proxyConfig.type || "socks";
      els.pHost.value = res.proxyConfig.host || "127.0.0.1";
      els.pPort.value = res.proxyConfig.port || 1080;
      els.pUser.value = res.proxyConfig.username || "";
      els.pPass.value = res.proxyConfig.password || "";
    }
    renderLists();
    try {
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      if (tabs[0] && tabs[0].url) {
        activeTab = tabs[0];
        const host = new URL(activeTab.url).hostname;
        if (host) els.domainInput.value = toGuiRule(host);
      }
    } catch (_) {}
    refreshIcon();
    if (res.lastProxyError) flash(els.pStatus, res.lastProxyError, "#ff6b6b");
  }

  els.saveProxy.addEventListener("click", async () => {
    const c = { 
      type: els.pType.value, host: els.pHost.value.trim(), port: Number(els.pPort.value),
      username: els.pUser.value.trim(), password: els.pPass.value.trim()
    };
    if (!c.host || !c.port) return flash(els.pStatus, "Заполните хост и порт", "#ff6b6b");
    await browser.storage.local.set({ proxyConfig: c });
    flash(els.pStatus, "Сохранено");
  });

  els.toggleRule.addEventListener("click", async () => {
    const rule = toGuiRule(els.domainInput.value);
    if (!rule) return flash(els.rulesStatus, "Пустое правило", "#ff6b6b");
    els.domainInput.value = rule;
    if (hasUserRule(rule)) {
      currentRules = currentRules.filter(i => normalize(i) !== normalize(rule));
      await saveRules();
      refreshIcon();
      flash(els.rulesStatus, "Удалено");
    } else {
      currentRules.push(rule);
      await saveRules();
      refreshIcon();
      flash(els.rulesStatus, "Добавлено");
    }
    await refreshDomainsPanel();
    checkAutoReload(rule);
  });

  els.viewDomains.addEventListener("click", async () => {
    domainsPanelOpen = !domainsPanelOpen;
    els.domainsPanel.classList.toggle("open", domainsPanelOpen);
    if (domainsPanelOpen) await refreshDomainsPanel();
  });

  els.addList.addEventListener("click", async () => {
    const url = els.lUrl.value.trim();
    if (!url.startsWith("http")) return flash(els.lStatus, "Введите корректный URL", "#ff6b6b");
    els.addList.disabled = true;
    els.addList.textContent = "Загрузка...";
    try {
      const res = await Promise.race([
        browser.runtime.sendMessage({ action: "fetchList", url, type: els.lAct.value }),
        new Promise((_, reject) => setTimeout(() => reject(new Error("Таймаут загрузки списка")), 60000))
      ]);
      if (res && res.success) { els.lUrl.value = ""; flash(els.lStatus, "Список применен!"); }
      else flash(els.lStatus, (res && res.error) ? String(res.error).slice(0, 180) : "Ошибка скачивания", "#ff6b6b");
    } catch (e) {
      flash(els.lStatus, String(e.message || e).slice(0, 180), "#ff6b6b");
    } finally {
      els.addList.disabled = false;
      els.addList.textContent = "Скачать и применить список";
    }
  });

  els.refreshLists.addEventListener("click", async () => {
    if (!currentLists.length) return flash(els.lStatus, "Списков нет", "#ff6b6b");
    els.refreshLists.disabled = true;
    els.refreshLists.textContent = "Обновление...";
    try {
      const res = await Promise.race([
        browser.runtime.sendMessage({ action: "refreshLists" }),
        new Promise((_, reject) => setTimeout(() => reject(new Error("Таймаут обновления")), 60000))
      ]);
      if (res && res.success) flash(els.lStatus, `Обновлено: ${res.updated || 0}`);
      else flash(els.lStatus, (res && res.error) ? String(res.error).slice(0, 180) : "Ошибка обновления", "#ff6b6b");
    } catch (e) {
      flash(els.lStatus, String(e.message || e).slice(0, 180), "#ff6b6b");
    } finally {
      els.refreshLists.disabled = false;
      els.refreshLists.textContent = "Обновить списки";
    }
  });

  els.openList.addEventListener("click", () => browser.tabs.create({ url: "list.html" }));
  els.domainInput.addEventListener("input", refreshIcon);

  browser.storage.onChanged.addListener((c, a) => {
    if (a !== "local") return;
    if (c.proxyRules) {
      currentRules = c.proxyRules.newValue || [];
      refreshIcon();
      refreshDomainsPanel();
    }
    if (c.proxyLists) { currentLists = c.proxyLists.newValue || []; renderLists(); }
    if (c.lastProxyError && c.lastProxyError.newValue) flash(els.pStatus, c.lastProxyError.newValue, "#ff6b6b");
  });

  await refreshAccessErrors();
  await loadState();
});
