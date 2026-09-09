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
    cancelDomains: document.getElementById("cancelDomainsBtn"),
    rulesStatus: document.getElementById("rulesStatus"), openList: document.getElementById("openListBtn"),
    pType: document.getElementById("proxyType"), pHost: document.getElementById("proxyHost"),
    pPort: document.getElementById("proxyPort"), pUser: document.getElementById("proxyUser"),
    pPass: document.getElementById("proxyPass"), saveProxy: document.getElementById("saveProxyBtn"),
    pStatus: document.getElementById("proxyStatus"), pFormStatus: document.getElementById("proxyFormStatus"),
    proxyMain: document.getElementById("proxyMain"), proxyForm: document.getElementById("proxyForm"),
    proxyEmpty: document.getElementById("proxyEmpty"), pCont: document.getElementById("proxyContainer"),
    showAddProxy: document.getElementById("showAddProxyBtn"), deleteProxy: document.getElementById("deleteProxyBtn"),
    cancelProxy: document.getElementById("cancelProxyBtn"),
    listsMain: document.getElementById("listsMain"), listsForm: document.getElementById("listsForm"),
    listsEmpty: document.getElementById("listsEmpty"),
    lName: document.getElementById("listName"), lUrl: document.getElementById("listUrl"),
    lAct: document.getElementById("listAction"), lInterval: document.getElementById("listInterval"),
    lViaProxy: document.getElementById("listViaProxy"),
    showAddList: document.getElementById("showAddListBtn"), saveList: document.getElementById("saveListBtn"),
    deleteList: document.getElementById("deleteListBtn"), cancelList: document.getElementById("cancelListBtn"),
    refreshLists: document.getElementById("refreshListsBtn"), lCont: document.getElementById("listsContainer"),
    lStatus: document.getElementById("listStatus"), lFormStatus: document.getElementById("listFormStatus"),
    powerBtn: document.getElementById("powerBtn")
  };

  let currentRules = [];
  let currentLists = [];
  let currentProxies = [];
  let activeTab = null;
  let domainsPanelOpen = false;
  let pageHost = "";
  let pageApex = "";
  let scopeMode = "host";
  let editingListId = null;
  let editingProxyId = null;
  let extensionEnabled = false;
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
  function coveringParentRule(host) {
    const exact = toGuiRule(host);
    return currentRules.find(r => normalize(r) !== normalize(exact) && matches(host, r)) || "";
  }
  function currentTargetRule() {
    if (scopeMode === "apex" && pageApex) return toGuiRule(pageApex);
    return toGuiRule(pageHost || els.domainInput.value);
  }
  function refreshCoveredNote() {
    if (scopeMode === "apex") {
      els.domainCovered.textContent = "";
      return;
    }
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
    const exact = hasUserRule(toGuiRule(v));
    const covered = !exact && currentRules.some(r => matches(v, r));
    els.statusIcon.className = "statusIcon" + (exact ? " in-list" : covered ? " covered" : "");
    els.statusIcon.textContent = exact ? "✓" : (covered ? "" : "❌");
    refreshToggleBtn();
    refreshCoveredNote();
  }
  function refreshToggleBtn() {
    const rule = toGuiRule(els.domainInput.value);
    const inList = hasUserRule(rule);
    els.toggleRule.textContent = inList ? "Удалить домен" : "Добавить домен";
    els.toggleRule.className = inList ? "danger" : "success";
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
    const uniq = [];
    (domains || []).forEach(d => {
      const h = String(d || "").trim().toLowerCase();
      if (h && uniq.indexOf(h) < 0) uniq.push(h);
    });
    uniq.sort();
    if (!uniq.length) {
      els.domainsEmpty.style.display = "block";
      return;
    }
    els.domainsEmpty.style.display = "none";
    function appendLine(parent, rule, kind, apex, bold) {
      const line = document.createElement("label");
      line.className = "domain-line";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.dataset.rule = rule;
      cb.dataset.kind = kind;
      cb.dataset.apex = apex;
      cb.checked = hasUserRule(rule);
      const text = document.createElement("span");
      text.className = bold ? "domain-name" : "domain-apex";
      text.textContent = rule;
      text.title = rule;
      line.appendChild(cb);
      line.appendChild(text);
      if (kind === "apex") {
        cb.addEventListener("change", () => {
          els.domainsList.querySelectorAll('input[data-kind="apex"]').forEach(box => {
            if (box.dataset.apex === apex) box.checked = cb.checked;
          });
        });
      }
      parent.appendChild(line);
    }
    uniq.forEach(host => {
      const apex = apexDomain(host) || host;
      const hostRule = toGuiRule(host);
      const apexRule = toGuiRule(apex);
      const item = document.createElement("div");
      item.className = "domain-item";
      const same = hostOfRule(hostRule) === apex;
      appendLine(item, hostRule, same ? "apex" : "host", apex, true);
      if (!same) appendLine(item, apexRule, "apex", apex, false);
      els.domainsList.appendChild(item);
    });
  }

  function closeDomainsPanel() {
    domainsPanelOpen = false;
    els.domainsPanel.classList.remove("open");
    els.viewDomains.classList.remove("open");
    els.domainsList.textContent = "";
  }

  function applyDomainDraft() {
    let added = 0, removed = 0;
    const listed = new Map();
    els.domainsList.querySelectorAll("input[type='checkbox']").forEach(cb => {
      const rule = cb.dataset.rule;
      if (!rule) return;
      const n = normalize(rule);
      const prev = listed.get(n);
      listed.set(n, { rule, want: cb.checked || (prev && prev.want) });
    });
    listed.forEach(({ rule, want }) => {
      if (want) {
        if (!hasUserRule(rule)) { currentRules.push(rule); added++; }
      } else if (hasUserRule(rule)) {
        currentRules = currentRules.filter(i => normalize(i) !== normalize(rule));
        removed++;
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

  const ICON_REFRESH = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-2.6-6.4"/><polyline points="21 3 21 9 15 9"/></svg>';
  const ICON_EDIT = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>';

  function formatListUpdated(ts) {
    const n = Number(ts);
    if (!(n > 0)) return "ещё не обновлялся";
    const d = new Date(n);
    const pad = v => String(v).padStart(2, "0");
    return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function listIconButton(label, svg) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.title = label;
    btn.setAttribute("aria-label", label);
    btn.innerHTML = svg;
    return btn;
  }

  function proxyTypeLabel(t) {
    if (t === "http") return "HTTP";
    if (t === "https") return "HTTPS";
    return "SOCKS5";
  }

  function proxyKey(p) {
    return `${(p.type || "socks").toLowerCase()}|${String(p.host || "").trim().toLowerCase()}|${Number(p.port)}`;
  }

  function configFromServers(list) {
    const on = (list || []).find(p => p.enabled && p.host && Number(p.port) > 0);
    if (!on) return { type: "socks", host: "", port: 0, username: "", password: "" };
    return {
      type: on.type || "socks",
      host: String(on.host).trim(),
      port: Number(on.port),
      username: on.username || "",
      password: on.password || ""
    };
  }

  function withActiveProxy(list, activeId) {
    const out = (list || []).map(p => Object.assign({}, p, { enabled: false }));
    if (!out.length) return out;
    const has = activeId != null && out.some(p => p.id === activeId);
    const id = has ? activeId : (out[0].id);
    out.forEach(p => { p.enabled = p.id === id; });
    return out;
  }

  function migrateProxies(res) {
    let list = Array.isArray(res.proxyServers) ? res.proxyServers.map(p => Object.assign({}, p)) : [];
    if (!list.length && res.proxyConfig && res.proxyConfig.host) {
      const c = res.proxyConfig;
      list = [{
        id: Date.now(),
        type: c.type || "socks",
        host: c.host,
        port: Number(c.port) || 1080,
        username: c.username || "",
        password: c.password || "",
        enabled: true
      }];
    }
    const keep = (list.find(p => p.enabled) || list[0] || {}).id;
    return withActiveProxy(list, keep);
  }

  async function persistProxies(list) {
    const prevHad = !!configFromServers(currentProxies).host;
    const keep = (list.find(p => p.enabled) || list[0] || {}).id;
    currentProxies = withActiveProxy(list, keep);
    const cfg = configFromServers(currentProxies);
    if (!cfg.host) extensionEnabled = false;
    else if (!prevHad) extensionEnabled = true;
    await browser.storage.local.set({
      proxyServers: currentProxies,
      proxyConfig: cfg,
      extensionEnabled
    });
    renderProxies();
    refreshPowerBtn();
  }

  function hasConfiguredProxy() {
    return !!configFromServers(currentProxies).host;
  }

  function refreshPowerBtn() {
    const on = extensionEnabled && hasConfiguredProxy();
    els.powerBtn.classList.toggle("on", on);
    els.powerBtn.classList.toggle("off", !on);
    const label = !hasConfiguredProxy() ? "Сначала добавьте прокси" : (on ? "Выключить расширение" : "Включить расширение");
    els.powerBtn.title = label;
    els.powerBtn.setAttribute("aria-label", label);
    els.powerBtn.setAttribute("aria-pressed", on ? "true" : "false");
  }

  function showProxyTab() {
    tabs.forEach(t => t.classList.remove("active"));
    panels.forEach(p => p.classList.remove("active"));
    document.getElementById("tabProxy").classList.add("active");
    document.getElementById("panelProxy").classList.add("active");
  }

  function renderProxies() {
    els.pCont.textContent = "";
    const empty = !currentProxies.length;
    els.proxyEmpty.style.display = empty ? "block" : "none";
    currentProxies.forEach(p => {
      const card = document.createElement("div");
      card.className = "list-card";
      const body = document.createElement("div");
      body.className = "list-card-body";
      const title = document.createElement("div");
      title.className = "list-card-title";
      title.textContent = `${p.host || ""}:${p.port || ""}`;
      title.title = title.textContent;
      const meta = document.createElement("div");
      meta.className = "list-card-meta";
      const bits = [proxyTypeLabel(p.type)];
      if (p.username) bits.push(p.username);
      meta.textContent = bits.join(" · ");
      body.appendChild(title);
      body.appendChild(meta);
      const side = document.createElement("div");
      side.className = "list-card-side";
      const tog = document.createElement("label");
      tog.className = "switch";
      tog.title = p.enabled ? "Активный прокси" : "Сделать активным";
      const inp = document.createElement("input");
      inp.type = "checkbox";
      inp.checked = !!p.enabled;
      const ui = document.createElement("span");
      ui.className = "switch-ui";
      tog.appendChild(inp);
      tog.appendChild(ui);
      inp.addEventListener("change", async () => {
        if (!inp.checked) {
          inp.checked = true;
          return;
        }
        await persistProxies(currentProxies.map(item => Object.assign({}, item, { enabled: item.id === p.id })));
        flash(els.pStatus, "Активный прокси выбран");
      });
      const editBtn = listIconButton("Редактировать", ICON_EDIT);
      editBtn.addEventListener("click", () => openProxyForm(p));
      side.appendChild(tog);
      side.appendChild(editBtn);
      card.appendChild(body);
      card.appendChild(side);
      els.pCont.appendChild(card);
    });
  }

  function showProxyMain() {
    editingProxyId = null;
    els.proxyForm.style.display = "none";
    els.proxyMain.style.display = "flex";
    renderProxies();
  }

  function resetProxyForm() {
    els.pType.value = "socks";
    els.pHost.value = "";
    els.pPort.value = "";
    els.pUser.value = "";
    els.pPass.value = "";
    els.pFormStatus.textContent = "";
  }

  function openProxyForm(item) {
    els.proxyMain.style.display = "none";
    els.proxyForm.style.display = "flex";
    els.pFormStatus.textContent = "";
    if (item) {
      editingProxyId = item.id;
      els.pType.value = item.type === "http" || item.type === "https" ? item.type : "socks";
      els.pHost.value = item.host || "";
      els.pPort.value = item.port || "";
      els.pUser.value = item.username || "";
      els.pPass.value = item.password || "";
      els.saveProxy.title = "Сохранить";
      els.saveProxy.setAttribute("aria-label", "Сохранить");
      els.deleteProxy.style.display = "flex";
    } else {
      editingProxyId = null;
      resetProxyForm();
      els.saveProxy.title = "Добавить прокси";
      els.saveProxy.setAttribute("aria-label", "Добавить прокси");
      els.deleteProxy.style.display = "none";
    }
  }

  function collectProxyForm() {
    return {
      type: els.pType.value,
      host: els.pHost.value.trim(),
      port: Number(els.pPort.value),
      username: els.pUser.value.trim(),
      password: els.pPass.value.trim()
    };
  }

  function renderLists() {
    els.lCont.textContent = "";
    const empty = !currentLists.length;
    els.listsEmpty.style.display = empty ? "block" : "none";
    currentLists.forEach(l => {
      const card = document.createElement("div");
      card.className = "list-card";
      const body = document.createElement("div");
      body.className = "list-card-body";
      const name = String(l.name || "").trim();
      if (name) {
        const title = document.createElement("div");
        title.className = "list-card-title";
        title.textContent = name;
        title.title = name;
        body.appendChild(title);
      }
      const meta = document.createElement("div");
      meta.className = "list-card-meta";
      const fmt = l.format === "pac" ? "PAC" : "txt";
      const kind = l.type === "block" ? "блокировать" : "проксировать";
      const domains = l.domainCount || (l.domains || []).length || 0;
      const ips = l.ipCount || (l.ips || []).length || 0;
      meta.textContent = `${fmt} · ${kind} · ${domains} дом. / ${ips} IP`;
      const urlLine = document.createElement("div");
      urlLine.className = "list-card-url";
      urlLine.textContent = l.url || "";
      urlLine.title = l.url || "";
      const updated = document.createElement("div");
      updated.className = "list-card-updated";
      const when = formatListUpdated(l.updatedAt);
      updated.textContent = `Обновлён: ${when}`;
      body.appendChild(meta);
      body.appendChild(urlLine);
      body.appendChild(updated);
      const actions = document.createElement("div");
      actions.className = "list-card-actions";
      const refreshBtn = listIconButton("Обновить", ICON_REFRESH);
      refreshBtn.addEventListener("click", () => refreshOneList(l.id, refreshBtn));
      const editBtn = listIconButton("Редактировать", ICON_EDIT);
      editBtn.addEventListener("click", () => openListForm(l));
      actions.appendChild(refreshBtn);
      actions.appendChild(editBtn);
      card.appendChild(body);
      card.appendChild(actions);
      els.lCont.appendChild(card);
    });
  }

  function canonListUrl(url) {
    return String(url || "").trim().replace(/\/+$/, "").toLowerCase();
  }

  function showListsMain() {
    editingListId = null;
    els.listsForm.style.display = "none";
    els.listsMain.style.display = "flex";
    renderLists();
  }

  function resetListForm() {
    els.lName.value = "";
    els.lUrl.value = "";
    els.lAct.value = "proxy";
    els.lInterval.value = "12";
    els.lViaProxy.checked = false;
    els.lFormStatus.textContent = "";
  }

  function openListForm(item) {
    els.listsMain.style.display = "none";
    els.listsForm.style.display = "flex";
    els.lFormStatus.textContent = "";
    if (item) {
      editingListId = item.id;
      els.lName.value = item.name || "";
      els.lUrl.value = item.url || "";
      els.lAct.value = item.type === "block" ? "block" : "proxy";
      els.lInterval.value = String(Number(item.intervalHours) > 0 ? Number(item.intervalHours) : 12);
      els.lViaProxy.checked = !!item.viaProxy;
      els.saveList.title = "Сохранить";
      els.saveList.setAttribute("aria-label", "Сохранить");
      els.deleteList.style.display = "flex";
    } else {
      editingListId = null;
      resetListForm();
      els.saveList.title = "Добавить список";
      els.saveList.setAttribute("aria-label", "Добавить список");
      els.deleteList.style.display = "none";
    }
  }

  function collectListForm() {
    const url = els.lUrl.value.trim();
    let hours = Number(els.lInterval.value);
    if (!(hours > 0)) hours = 12;
    if (hours > 168) hours = 168;
    return {
      url,
      name: els.lName.value.trim(),
      type: els.lAct.value,
      intervalHours: hours,
      viaProxy: !!els.lViaProxy.checked
    };
  }

  async function sendListMessage(payload) {
    return Promise.race([
      browser.runtime.sendMessage(payload),
      new Promise((_, reject) => setTimeout(() => reject(new Error("Таймаут")), 60000))
    ]);
  }

  async function refreshOneList(id, btn) {
    if (btn) { btn.disabled = true; btn.classList.add("busy"); }
    try {
      const res = await sendListMessage({ action: "refreshList", id });
      if (res && res.success) flash(els.lStatus, "Обновлено");
      else flash(els.lStatus, (res && res.error) ? String(res.error).slice(0, 180) : "Ошибка обновления", "#ff6b6b");
    } catch (e) {
      flash(els.lStatus, String(e.message || e).slice(0, 180), "#ff6b6b");
    } finally {
      if (btn) { btn.disabled = false; btn.classList.remove("busy"); }
    }
  }

  async function loadState() {
    const res = await browser.storage.local.get(["proxyConfig", "proxyServers", "proxyRules", "proxyLists", "lastProxyError", "extensionEnabled"]);
    currentRules = Array.isArray(res.proxyRules) ? res.proxyRules : [];
    currentLists = Array.isArray(res.proxyLists) ? res.proxyLists : [];
    currentProxies = Array.isArray(res.proxyServers) ? res.proxyServers.slice() : [];
    const migrated = migrateProxies(res);
    const cfg = configFromServers(migrated);
    if (res.extensionEnabled == null) extensionEnabled = !!cfg.host;
    else extensionEnabled = !!res.extensionEnabled && !!cfg.host;
    const prev = Array.isArray(res.proxyServers) ? res.proxyServers : [];
    if (JSON.stringify(migrated) !== JSON.stringify(prev) || res.extensionEnabled !== extensionEnabled) {
      await persistProxies(migrated);
    } else {
      currentProxies = migrated;
      renderProxies();
      refreshPowerBtn();
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

  els.showAddProxy.addEventListener("click", () => openProxyForm(null));
  els.cancelProxy.addEventListener("click", () => showProxyMain());

  els.saveProxy.addEventListener("click", async () => {
    const form = collectProxyForm();
    if (!form.host || !(form.port > 0 && form.port < 65536)) {
      return flash(els.pFormStatus, "Заполните хост и порт", "#ff6b6b");
    }
    const dup = currentProxies.find(p => proxyKey(p) === proxyKey(form) && p.id !== editingProxyId);
    if (dup) return flash(els.pFormStatus, "Прокси добавить нельзя, он уже существует", "#ff6b6b");
    if (editingProxyId != null) {
      const next = currentProxies.map(p => p.id === editingProxyId ? Object.assign({}, p, form) : p);
      await persistProxies(next);
      flash(els.pStatus, "Сохранено");
    } else {
      const item = Object.assign({ id: Date.now(), enabled: !currentProxies.length }, form);
      await persistProxies(currentProxies.concat(item));
      flash(els.pStatus, "Прокси добавлен");
    }
    showProxyMain();
  });

  els.deleteProxy.addEventListener("click", async () => {
    if (editingProxyId == null) return;
    await persistProxies(currentProxies.filter(p => p.id !== editingProxyId));
    flash(els.pStatus, "Удалено");
    showProxyMain();
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
    els.viewDomains.classList.add("open");
    await refreshDomainsPanel();
  });
  els.domainsPanel.addEventListener("click", (e) => {
    if (e.target === els.domainsPanel) closeDomainsPanel();
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
  els.cancelDomains.addEventListener("click", () => closeDomainsPanel());

  els.showAddList.addEventListener("click", () => openListForm(null));
  els.cancelList.addEventListener("click", () => showListsMain());

  els.saveList.addEventListener("click", async () => {
    const form = collectListForm();
    if (!form.url.startsWith("http")) return flash(els.lFormStatus, "Введите корректный URL", "#ff6b6b");
    const dup = currentLists.find(l => canonListUrl(l.url) === canonListUrl(form.url) && l.id !== editingListId);
    if (dup) return flash(els.lFormStatus, "Список добавить нельзя, он уже существует", "#ff6b6b");
    els.saveList.disabled = true;
    els.saveList.classList.add("busy");
    try {
      const existing = editingListId != null ? currentLists.find(l => l.id === editingListId) : null;
      const urlChanged = existing && canonListUrl(existing.url) !== canonListUrl(form.url);
      const proxyChanged = existing && !!existing.viaProxy !== form.viaProxy;
      const needFetch = !existing || urlChanged || proxyChanged;
      const res = await sendListMessage(needFetch
        ? { action: "fetchList", id: editingListId, url: form.url, type: form.type, name: form.name, intervalHours: form.intervalHours, viaProxy: form.viaProxy }
        : { action: "saveListMeta", id: editingListId, url: form.url, type: form.type, name: form.name, intervalHours: form.intervalHours, viaProxy: form.viaProxy });
      if (res && res.success) {
        flash(els.lStatus, existing ? "Сохранено" : "Список добавлен");
        showListsMain();
      } else flash(els.lFormStatus, (res && res.error) ? String(res.error).slice(0, 180) : "Ошибка", "#ff6b6b");
    } catch (e) {
      flash(els.lFormStatus, String(e.message || e).slice(0, 180), "#ff6b6b");
    } finally {
      els.saveList.disabled = false;
      els.saveList.classList.remove("busy");
    }
  });

  els.deleteList.addEventListener("click", async () => {
    if (editingListId == null) return;
    currentLists = currentLists.filter(x => x.id !== editingListId);
    await browser.storage.local.set({ proxyLists: currentLists });
    flash(els.lStatus, "Удалено");
    showListsMain();
  });

  els.refreshLists.addEventListener("click", async () => {
    if (!currentLists.length) return flash(els.lStatus, "Списков нет", "#ff6b6b");
    els.refreshLists.disabled = true;
    els.refreshLists.textContent = "Обновление...";
    try {
      const res = await sendListMessage({ action: "refreshLists" });
      if (res && res.success) flash(els.lStatus, `Обновлено: ${res.updated || 0}`);
      else flash(els.lStatus, (res && res.error) ? String(res.error).slice(0, 180) : "Ошибка обновления", "#ff6b6b");
    } catch (e) {
      flash(els.lStatus, String(e.message || e).slice(0, 180), "#ff6b6b");
    } finally {
      els.refreshLists.disabled = false;
      els.refreshLists.textContent = "Обновить все";
    }
  });

  els.openList.addEventListener("click", () => {
    browser.tabs.create({ url: "list.html" }).finally(() => window.close());
  });
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

  els.powerBtn.addEventListener("click", async () => {
    if (!hasConfiguredProxy()) {
      showProxyTab();
      flash(els.pStatus, "Сначала добавьте прокси", "#ff6b6b");
      return;
    }
    extensionEnabled = !extensionEnabled;
    await browser.storage.local.set({ extensionEnabled });
    refreshPowerBtn();
  });

  browser.storage.onChanged.addListener((c, a) => {
    if (a !== "local") return;
    if (c.proxyRules) {
      currentRules = c.proxyRules.newValue || [];
      refreshIcon();
    }
    if (c.proxyLists) { currentLists = c.proxyLists.newValue || []; renderLists(); }
    if (c.proxyServers) {
      currentProxies = migrateProxies({ proxyServers: c.proxyServers.newValue || [] });
      renderProxies();
      refreshPowerBtn();
    }
    if (c.extensionEnabled) {
      extensionEnabled = !!c.extensionEnabled.newValue && hasConfiguredProxy();
      refreshPowerBtn();
    }
    if (c.lastProxyError && c.lastProxyError.newValue) flash(els.pStatus, c.lastProxyError.newValue, "#ff6b6b");
  });

  await refreshAccessErrors();
  await loadState();
});
