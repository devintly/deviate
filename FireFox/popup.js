document.addEventListener("DOMContentLoaded", async () => {
  const tabs = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".panel");
  const els = {
    domainInput: document.getElementById("domainInput"), statusIcon: document.getElementById("statusIcon"),
    toggleRule: document.getElementById("toggleRuleBtn"), viewDomains: document.getElementById("viewDomainsBtn"),
    scopeHost: document.getElementById("scopeHostBtn"), scopeApex: document.getElementById("scopeApexBtn"),
    domainScope: document.getElementById("domainScope"), domainCovered: document.getElementById("domainCovered"),
    domainsPanel: document.getElementById("domainsPanel"), domainsList: document.getElementById("domainsList"),
    domainsEmpty: document.getElementById("domainsEmpty"), saveDomains: document.getElementById("saveDomainsBtn"),
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
  let pageHost = "";
  let pageApex = "";
  let scopeMode = "host";
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
  function isIpHost(h) {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || (h || "").indexOf(":") >= 0;
  }
  const MULTI_SUFFIX = {
    "ac.uk":1,"co.uk":1,"gov.uk":1,"ltd.uk":1,"me.uk":1,"net.uk":1,"org.uk":1,"plc.uk":1,"sch.uk":1,
    "com.au":1,"net.au":1,"org.au":1,"edu.au":1,"gov.au":1,"asn.au":1,"id.au":1,
    "co.nz":1,"net.nz":1,"org.nz":1,"co.jp":1,"ne.jp":1,"or.jp":1,"ac.jp":1,"go.jp":1,
    "com.br":1,"net.br":1,"org.br":1,"com.tr":1,"com.ua":1,"co.ua":1,"org.ua":1,
    "com.cn":1,"net.cn":1,"org.cn":1,"com.tw":1,"com.hk":1,"co.kr":1,"com.mx":1,
    "co.za":1,"co.in":1,"net.in":1,"org.in":1,"co.il":1,"com.sg":1
  };
  function apexDomain(host) {
    const h = normalize(host).replace(/^\*\./, "");
    if (!h || isIpHost(h)) return h;
    const parts = h.split(".").filter(Boolean);
    if (parts.length <= 2) return h;
    const last2 = parts.slice(-2).join(".");
    if (MULTI_SUFFIX[last2] && parts.length >= 3) return parts.slice(-3).join(".");
    return last2;
  }
  function hostOfRule(rule) { return normalize(rule).replace(/^\*\./, ""); }
  function isUnderApex(rule, apex) {
    const h = hostOfRule(rule);
    return !!apex && (h === apex || h.endsWith("." + apex));
  }
  function coveringParentRule(host) {
    const exact = toGuiRule(host);
    return currentRules.find(r => normalize(r) !== normalize(exact) && matches(host, r)) || "";
  }
  function currentTargetRule() {
    if (scopeMode === "apex" && pageApex) return toGuiRule(pageApex);
    return toGuiRule(pageHost || els.domainInput.value);
  }
  function formatHostList(arr, max) {
    if (!arr.length) return "";
    if (arr.length <= max) return arr.join(", ");
    return arr.slice(0, max).join(", ") + " и ещё " + (arr.length - max);
  }
  function groupHostsByApex(hosts) {
    const map = new Map();
    hosts.forEach(host => {
      const h = String(host || "").trim().toLowerCase();
      if (!h) return;
      const apex = apexDomain(h) || h;
      if (!map.has(apex)) map.set(apex, []);
      if (map.get(apex).indexOf(h) < 0) map.get(apex).push(h);
    });
    return Array.from(map.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  }
  function refreshCoveredNote() {
    const host = pageHost || hostOfRule(els.domainInput.value);
    const parent = coveringParentRule(host);
    const exact = toGuiRule(host);
    if (parent && !hasUserRule(exact)) els.domainCovered.textContent = `Покрыто правилом ${parent}`;
    else els.domainCovered.textContent = "";
  }
  function refreshScopeUI() {
    const hasChoice = !!(pageHost && pageApex && pageHost !== pageApex && !isIpHost(pageHost));
    els.domainScope.classList.toggle("show", hasChoice);
    if (hasChoice) {
      els.scopeHost.textContent = `Этот: ${toGuiRule(pageHost)}`;
      els.scopeApex.textContent = `Основной: ${toGuiRule(pageApex)}`;
      els.scopeHost.classList.toggle("active", scopeMode === "host");
      els.scopeApex.classList.toggle("active", scopeMode === "apex");
    } else {
      scopeMode = "host";
    }
    refreshCoveredNote();
  }
  function setScope(mode, writeInput) {
    scopeMode = mode === "apex" ? "apex" : "host";
    if (writeInput) {
      const rule = currentTargetRule();
      if (rule) els.domainInput.value = rule;
    }
    refreshScopeUI();
    refreshIcon();
  }
  function refreshIcon() {
    const v = els.domainInput.value.trim();
    els.statusIcon.textContent = currentRules.some(r => matches(v, r)) ? "✅" : "❌";
    refreshToggleBtn();
    refreshCoveredNote();
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
    const groups = groupHostsByApex(domains);
    if (!groups.length) {
      els.domainsEmpty.style.display = "block";
      return;
    }
    els.domainsEmpty.style.display = "none";
    groups.forEach(([apex, hosts]) => {
      const rule = toGuiRule(apex);
      const inList = hasUserRule(rule);
      const extras = hosts.filter(h => h !== apex && h !== "www." + apex);
      const specific = currentRules.filter(r => {
        const hr = hostOfRule(r);
        return hr && hr !== apex && isUnderApex(r, apex);
      });
      const row = document.createElement("label");
      row.className = "domain-check";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.dataset.rule = rule;
      cb.dataset.apex = apex;
      cb.checked = inList;
      const meta = document.createElement("div");
      meta.className = "domain-meta";
      const name = document.createElement("span");
      name.className = "domain-name";
      name.textContent = rule;
      name.title = hosts.join(", ");
      meta.appendChild(name);
      const notes = [];
      if (extras.length) notes.push("на вкладке: " + formatHostList(extras, 3));
      if (inList) notes.push("покрывает все поддомены");
      else if (specific.length) notes.push("уже в правилах: " + formatHostList(specific, 3));
      if (notes.length) {
        const note = document.createElement("span");
        note.className = "domain-note" + (inList || specific.length ? " covered" : "");
        note.textContent = notes.join(" · ");
        meta.appendChild(note);
      }
      row.appendChild(cb);
      row.appendChild(meta);
      els.domainsList.appendChild(row);
    });
  }

  function closeDomainsPanel() {
    domainsPanelOpen = false;
    els.domainsPanel.classList.remove("open");
    els.domainsList.textContent = "";
  }

  function applyDomainDraft() {
    let added = 0, removed = 0;
    els.domainsList.querySelectorAll("input[type='checkbox']").forEach(cb => {
      const rule = cb.dataset.rule;
      const apex = cb.dataset.apex || hostOfRule(rule);
      if (!rule) return;
      if (cb.checked) {
        if (!hasUserRule(rule)) { currentRules.push(rule); added++; }
        const before = currentRules.length;
        currentRules = currentRules.filter(r => normalize(r) === normalize(rule) || !isUnderApex(r, apex));
        if (currentRules.length < before) removed += before - currentRules.length;
      } else if (currentRules.some(r => isUnderApex(r, apex))) {
        const before = currentRules.length;
        currentRules = currentRules.filter(r => !isUnderApex(r, apex));
        removed += before - currentRules.length;
      }
    });
    return { added, removed };
  }

  async function reloadActiveTab() {
    if (activeTab && activeTab.id != null) {
      try { await browser.tabs.reload(activeTab.id); } catch (_) {}
    }
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
        if (host) {
          pageHost = normalize(host).replace(/^\*\./, "");
          pageApex = apexDomain(pageHost);
          scopeMode = "host";
          els.domainInput.value = toGuiRule(pageHost);
        }
      }
    } catch (_) {}
    refreshScopeUI();
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
    if (domainsPanelOpen) {
      els.domainsList.querySelectorAll("input[type='checkbox']").forEach(box => {
        if (normalize(box.dataset.rule) === normalize(rule)) box.checked = hasUserRule(rule);
      });
    }
    checkAutoReload(rule);
  });

  els.scopeHost.addEventListener("click", () => setScope("host", true));
  els.scopeApex.addEventListener("click", () => setScope("apex", true));

  els.viewDomains.addEventListener("click", async () => {
    if (domainsPanelOpen) {
      closeDomainsPanel();
      return;
    }
    domainsPanelOpen = true;
    els.domainsPanel.classList.add("open");
    await refreshDomainsPanel();
  });

  els.saveDomains.addEventListener("click", async () => {
    const { added, removed } = applyDomainDraft();
    if (added || removed) {
      await saveRules();
      refreshIcon();
      const parts = [];
      if (added) parts.push(`добавлено: ${added}`);
      if (removed) parts.push(`удалено: ${removed}`);
      flash(els.rulesStatus, parts.join(", "));
    }
    closeDomainsPanel();
    if (added || removed) await reloadActiveTab();
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
  els.domainInput.addEventListener("input", () => {
    const h = hostOfRule(els.domainInput.value);
    if (h) {
      pageHost = h;
      pageApex = apexDomain(h);
      if (pageApex && h === pageApex) scopeMode = "host";
    }
    refreshScopeUI();
    refreshIcon();
  });

  browser.storage.onChanged.addListener((c, a) => {
    if (a !== "local") return;
    if (c.proxyRules) {
      currentRules = c.proxyRules.newValue || [];
      refreshIcon();
    }
    if (c.proxyLists) { currentLists = c.proxyLists.newValue || []; renderLists(); }
    if (c.lastProxyError && c.lastProxyError.newValue) flash(els.pStatus, c.lastProxyError.newValue, "#ff6b6b");
  });

  await refreshAccessErrors();
  await loadState();
});
