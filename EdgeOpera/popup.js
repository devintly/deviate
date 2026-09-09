const api = typeof browser !== "undefined" ? browser : chrome;

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
    pStatus: document.getElementById("proxyStatus"),
    listsMain: document.getElementById("listsMain"), listsForm: document.getElementById("listsForm"),
    listsEmpty: document.getElementById("listsEmpty"),
    lName: document.getElementById("listName"), lUrl: document.getElementById("listUrl"),
    lAct: document.getElementById("listAction"), lInterval: document.getElementById("listInterval"),
    lViaProxy: document.getElementById("listViaProxy"),
    showAddList: document.getElementById("showAddListBtn"), saveList: document.getElementById("saveListBtn"),
    deleteList: document.getElementById("deleteListBtn"), cancelList: document.getElementById("cancelListBtn"),
    refreshLists: document.getElementById("refreshListsBtn"), lCont: document.getElementById("listsContainer"),
    lStatus: document.getElementById("listStatus"), lFormStatus: document.getElementById("listFormStatus")
  };

  let currentRules = [];
  let currentLists = [];
  let activeTab = null;
  let domainsPanelOpen = false;
  let pageHost = "";
  let pageApex = "";
  let scopeMode = "host";
  let editingListId = null;
  const HOST_ORIGINS = ["http://*/*", "https://*/*", "ws://*/*", "wss://*/*"];
  const accessError = document.getElementById("accessError");
  const accessErrorText = document.getElementById("accessErrorText");

  function containsOrigins() {
    return new Promise((resolve) => {
      if (!api.permissions || !api.permissions.contains) return resolve(true);
      api.permissions.contains({ origins: HOST_ORIGINS }, (ok) => resolve(!!ok));
    });
  }

  async function refreshAccessErrors() {
    const msgs = [];
    try {
      if (!(await containsOrigins())) msgs.push("Нет доступа к сайтам. Включите его в разрешениях расширения — без этого прокси по спискам не работает.");
    } catch (e) {}
    if (accessError && accessErrorText) {
      accessErrorText.textContent = msgs.join("\n\n");
      accessError.style.display = msgs.length ? "block" : "none";
    }
  }

  if (api.permissions && api.permissions.onAdded) {
    api.permissions.onAdded.addListener(refreshAccessErrors);
  }
  if (api.permissions && api.permissions.onRemoved) {
    api.permissions.onRemoved.addListener(refreshAccessErrors);
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
    els.toggleRule.className = inList ? "danger" : "primary";
    els.toggleRule.disabled = !rule;
  }
  function flash(el, t, c = "#57f287") {
    el.style.color = c; el.textContent = t;
    setTimeout(() => { if (el.textContent === t) el.textContent = ""; }, 2000);
  }

  function checkAutoReload(rule) {
    if (activeTab && activeTab.url) {
      const url = new URL(activeTab.url);
      if (matches(url.hostname, rule) && api.tabs.reload) api.tabs.reload(activeTab.id);
    }
  }

  function saveRules(done) {
    api.storage.local.set({ proxyRules: currentRules }, () => { if (done) done(); });
  }

  function fetchTabDomains() {
    return new Promise((resolve) => {
      const set = new Set();
      if (activeTab && activeTab.url) {
        try {
          const host = new URL(activeTab.url).hostname;
          if (host) set.add(host.toLowerCase());
        } catch (_) {}
      }
      if (!activeTab) return resolve(Array.from(set).sort());
      api.runtime.sendMessage({ action: "getTabDomains", tabId: activeTab.id }, (res) => {
        if (api.runtime.lastError) {}
        (res && res.domains ? res.domains : []).forEach(d => {
          const h = String(d || "").trim().toLowerCase();
          if (h) set.add(h);
        });
        resolve(Array.from(set).sort());
      });
    });
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

  function reloadActiveTab() {
    if (activeTab && activeTab.id != null && api.tabs.reload) api.tabs.reload(activeTab.id);
  }

  function refreshDomainsPanel() {
    if (!domainsPanelOpen) return;
    fetchTabDomains().then(renderDomainsList);
  }

  function renderLists() {
    els.lCont.textContent = "";
    const empty = !currentLists.length;
    els.listsEmpty.style.display = empty ? "block" : "none";
    currentLists.forEach(l => {
      const card = document.createElement("div");
      card.className = "list-card";
      const name = String(l.name || "").trim();
      if (name) {
        const title = document.createElement("div");
        title.className = "list-card-title";
        title.textContent = name;
        title.title = name;
        card.appendChild(title);
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
      const actions = document.createElement("div");
      actions.className = "list-card-actions";
      const refreshBtn = document.createElement("button");
      refreshBtn.type = "button";
      refreshBtn.className = "mini-primary";
      refreshBtn.textContent = "Обновить";
      refreshBtn.addEventListener("click", () => refreshOneList(l.id, refreshBtn));
      const editBtn = document.createElement("button");
      editBtn.type = "button";
      editBtn.textContent = "Редактировать";
      editBtn.addEventListener("click", () => openListForm(l));
      actions.appendChild(refreshBtn);
      actions.appendChild(editBtn);
      card.appendChild(meta);
      card.appendChild(urlLine);
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
    els.listsMain.style.display = "block";
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
    els.listsForm.style.display = "block";
    els.lFormStatus.textContent = "";
    if (item) {
      editingListId = item.id;
      els.lName.value = item.name || "";
      els.lUrl.value = item.url || "";
      els.lAct.value = item.type === "block" ? "block" : "proxy";
      els.lInterval.value = String(Number(item.intervalHours) > 0 ? Number(item.intervalHours) : 12);
      els.lViaProxy.checked = !!item.viaProxy;
      els.saveList.textContent = "Сохранить";
      els.deleteList.style.display = "flex";
    } else {
      editingListId = null;
      resetListForm();
      els.saveList.textContent = "Добавить список";
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

  function sendListMessage(payload) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Таймаут")), 60000);
      api.runtime.sendMessage(payload, (res) => {
        clearTimeout(timer);
        if (api.runtime.lastError) return reject(new Error(api.runtime.lastError.message || "Фон расширения не ответил"));
        resolve(res);
      });
    });
  }

  function refreshOneList(id, btn) {
    if (btn) { btn.disabled = true; btn.textContent = "..."; }
    sendListMessage({ action: "refreshList", id }).then(res => {
      if (res && res.success) flash(els.lStatus, "Обновлено");
      else flash(els.lStatus, (res && res.error) ? String(res.error).slice(0, 180) : "Ошибка обновления", "#ff6b6b");
    }).catch(e => {
      flash(els.lStatus, String(e.message || e).slice(0, 180), "#ff6b6b");
    }).finally(() => {
      if (btn) { btn.disabled = false; btn.textContent = "Обновить"; }
    });
  }

  function loadState() {
    api.storage.local.get(["proxyConfig", "proxyRules", "proxyLists", "lastProxyError"], (res) => {
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
      api.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].url) {
          activeTab = tabs[0];
          try {
             const host = new URL(activeTab.url).hostname;
             if (host) {
               pageHost = normalize(host).replace(/^\*\./, "");
               pageApex = apexDomain(pageHost);
               scopeMode = "host";
               els.domainInput.value = toGuiRule(pageHost);
             }
          } catch(e){}
        }
        refreshScopeUI();
        refreshIcon();
        if (res.lastProxyError) flash(els.pStatus, res.lastProxyError, "#ff6b6b");
      });
    });
  }

  els.saveProxy.addEventListener("click", () => {
    const c = { 
      type: els.pType.value, host: els.pHost.value.trim(), port: Number(els.pPort.value),
      username: els.pUser.value.trim(), password: els.pPass.value.trim()
    };
    if (!c.host || !c.port) return flash(els.pStatus, "Заполните хост и порт", "#ff6b6b");
    api.storage.local.set({ proxyConfig: c }, () => {
       flash(els.pStatus, "Сохранено");
    });
  });

  els.toggleRule.addEventListener("click", () => {
    const rule = toGuiRule(els.domainInput.value);
    if (!rule) return flash(els.rulesStatus, "Пустое правило", "#ff6b6b");
    els.domainInput.value = rule;
    if (hasUserRule(rule)) {
      currentRules = currentRules.filter(i => normalize(i) !== normalize(rule));
      saveRules(() => {
        refreshIcon();
        flash(els.rulesStatus, "Удалено");
        if (domainsPanelOpen) {
          els.domainsList.querySelectorAll("input[type='checkbox']").forEach(box => {
            if (normalize(box.dataset.rule) === normalize(rule)) box.checked = hasUserRule(rule);
          });
        }
        checkAutoReload(rule);
      });
    } else {
      currentRules.push(rule);
      saveRules(() => {
        refreshIcon();
        flash(els.rulesStatus, "Добавлено");
        if (domainsPanelOpen) {
          els.domainsList.querySelectorAll("input[type='checkbox']").forEach(box => {
            if (normalize(box.dataset.rule) === normalize(rule)) box.checked = hasUserRule(rule);
          });
        }
        checkAutoReload(rule);
      });
    }
  });

  els.scopeHost.addEventListener("click", () => setScope("host", true));
  els.scopeApex.addEventListener("click", () => setScope("apex", true));

  els.viewDomains.addEventListener("click", () => {
    if (domainsPanelOpen) {
      closeDomainsPanel();
      return;
    }
    domainsPanelOpen = true;
    els.domainsPanel.classList.add("open");
    refreshDomainsPanel();
  });

  els.saveDomains.addEventListener("click", () => {
    const { added, removed } = applyDomainDraft();
    const finish = () => {
      closeDomainsPanel();
      if (added || removed) reloadActiveTab();
    };
    if (added || removed) {
      saveRules(() => {
        refreshIcon();
        const parts = [];
        if (added) parts.push(`добавлено: ${added}`);
        if (removed) parts.push(`удалено: ${removed}`);
        flash(els.rulesStatus, parts.join(", "));
        finish();
      });
    } else {
      finish();
    }
  });

  els.showAddList.addEventListener("click", () => openListForm(null));
  els.cancelList.addEventListener("click", () => showListsMain());

  els.saveList.addEventListener("click", () => {
    const form = collectListForm();
    if (!form.url.startsWith("http")) return flash(els.lFormStatus, "Введите корректный URL", "#ff6b6b");
    const dup = currentLists.find(l => canonListUrl(l.url) === canonListUrl(form.url) && l.id !== editingListId);
    if (dup) return flash(els.lFormStatus, "Список добавить нельзя, он уже существует", "#ff6b6b");
    els.saveList.disabled = true;
    const prev = els.saveList.textContent;
    els.saveList.textContent = editingListId ? "Сохранение..." : "Загрузка...";
    const existing = editingListId != null ? currentLists.find(l => l.id === editingListId) : null;
    const urlChanged = existing && canonListUrl(existing.url) !== canonListUrl(form.url);
    const proxyChanged = existing && !!existing.viaProxy !== form.viaProxy;
    const needFetch = !existing || urlChanged || proxyChanged;
    const payload = needFetch
      ? { action: "fetchList", id: editingListId, url: form.url, type: form.type, name: form.name, intervalHours: form.intervalHours, viaProxy: form.viaProxy }
      : { action: "saveListMeta", id: editingListId, url: form.url, type: form.type, name: form.name, intervalHours: form.intervalHours, viaProxy: form.viaProxy };
    sendListMessage(payload).then(res => {
      if (res && res.success) {
        flash(els.lStatus, existing ? "Сохранено" : "Список добавлен");
        showListsMain();
      } else flash(els.lFormStatus, (res && res.error) ? String(res.error).slice(0, 180) : "Ошибка", "#ff6b6b");
    }).catch(e => {
      flash(els.lFormStatus, String(e.message || e).slice(0, 180), "#ff6b6b");
    }).finally(() => {
      els.saveList.disabled = false;
      els.saveList.textContent = prev;
    });
  });

  els.deleteList.addEventListener("click", () => {
    if (editingListId == null) return;
    currentLists = currentLists.filter(x => x.id !== editingListId);
    api.storage.local.set({ proxyLists: currentLists }, () => {
      flash(els.lStatus, "Удалено");
      showListsMain();
    });
  });

  els.refreshLists.addEventListener("click", () => {
    if (!currentLists.length) return flash(els.lStatus, "Списков нет", "#ff6b6b");
    els.refreshLists.disabled = true;
    els.refreshLists.textContent = "Обновление...";
    sendListMessage({ action: "refreshLists" }).then(res => {
      if (res && res.success) flash(els.lStatus, `Обновлено: ${res.updated || 0}`);
      else flash(els.lStatus, (res && res.error) ? String(res.error).slice(0, 180) : "Ошибка обновления", "#ff6b6b");
    }).catch(e => {
      flash(els.lStatus, String(e.message || e).slice(0, 180), "#ff6b6b");
    }).finally(() => {
      els.refreshLists.disabled = false;
      els.refreshLists.textContent = "Обновить все";
    });
  });

  els.openList.addEventListener("click", () => {
      const url = api.runtime.getURL("list.html");
      api.tabs.create({ url: url }, () => window.close());
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
  
  api.storage.onChanged.addListener((c, a) => {
    if (a !== "local") return;
    if (c.proxyRules) {
      currentRules = c.proxyRules.newValue || [];
      refreshIcon();
    }
    if (c.proxyLists) { currentLists = c.proxyLists.newValue || []; renderLists(); }
    if (c.lastProxyError && c.lastProxyError.newValue) flash(els.pStatus, c.lastProxyError.newValue, "#ff6b6b");
  });

  await refreshAccessErrors();
  loadState();
});
