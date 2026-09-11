const browser = globalThis.browser || globalThis.chrome;

document.addEventListener("DOMContentLoaded", async () => {
  if (typeof I18n !== "undefined") await I18n.init(browser);
  try {
    const plat = await browser.runtime.getPlatformInfo();
    if (plat && plat.os === "android") document.documentElement.classList.add("android");
  } catch (_) {}

  function ownPageBase() {
    try { return browser.runtime.getURL(""); } catch (_) { return ""; }
  }
  function isOwnPage(url) {
    const s = String(url || "");
    if (!s) return false;
    const base = ownPageBase();
    return !!(base && s.indexOf(base) === 0);
  }
  function isWebTab(tab) {
    if (!tab || isOwnPage(tab.url)) return false;
    try {
      const p = new URL(tab.url).protocol;
      return p === "http:" || p === "https:";
    } catch (_) {
      return false;
    }
  }
  async function queryActiveTab() {
    async function activeWeb(query) {
      const found = await browser.tabs.query(query);
      const tab = (found && found[0]) || null;
      return isWebTab(tab) ? tab : null;
    }
    try {
      const tab = await activeWeb({ active: true, currentWindow: true });
      if (tab) return tab;
    } catch (_) {}
    try {
      return await activeWeb({ active: true });
    } catch (_) {}
    return null;
  }

  const tabs = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".panel");
  const els = {
    domainInput: document.getElementById("domainInput"), statusIcon: document.getElementById("statusIcon"),
    toggleRule: document.getElementById("toggleRuleBtn"), viewDomains: document.getElementById("viewDomainsBtn"),
    domainActionRow: document.getElementById("domainActionRow"), domainMode: document.getElementById("domainModeSwitch"),
    domainDirect: document.getElementById("domainDirect"),
    scopeHost: document.getElementById("scopeHostBtn"), scopeApex: document.getElementById("scopeApexBtn"),
    domainScope: document.getElementById("domainScope"),
    domainsPanel: document.getElementById("domainsPanel"), domainsList: document.getElementById("domainsList"),
    domainsSearch: document.getElementById("domainsSearch"),
    domainsEmpty: document.getElementById("domainsEmpty"), saveDomains: document.getElementById("saveDomainsBtn"),
    cancelDomains: document.getElementById("cancelDomainsBtn"),
    rulesStatus: document.getElementById("rulesStatus"), openList: document.getElementById("openListBtn"),
    pName: document.getElementById("proxyName"),
    pType: document.getElementById("proxyType"), pHost: document.getElementById("proxyHost"),
    pPort: document.getElementById("proxyPort"), pUser: document.getElementById("proxyUser"),
    pPass: document.getElementById("proxyPass"), saveProxy: document.getElementById("saveProxyBtn"),
    pStatus: document.getElementById("proxyStatus"), pFormStatus: document.getElementById("proxyFormStatus"),
    proxyMain: document.getElementById("proxyMain"), proxyForm: document.getElementById("proxyForm"),
    proxyEmpty: document.getElementById("proxyEmpty"), pCont: document.getElementById("proxyContainer"),
    proxySearch: document.getElementById("proxySearch"),
    showAddProxy: document.getElementById("showAddProxyBtn"), deleteProxy: document.getElementById("deleteProxyBtn"),
    cancelProxy: document.getElementById("cancelProxyBtn"),
    listsMain: document.getElementById("listsMain"), listsForm: document.getElementById("listsForm"),
    listsEmpty: document.getElementById("listsEmpty"), listsSearch: document.getElementById("listsSearch"),
    lName: document.getElementById("listName"), lUrl: document.getElementById("listUrl"),
    lInterval: document.getElementById("listInterval"),
    lViaProxy: document.getElementById("listViaProxy"),
    showAddList: document.getElementById("showAddListBtn"), saveList: document.getElementById("saveListBtn"),
    deleteList: document.getElementById("deleteListBtn"), cancelList: document.getElementById("cancelListBtn"),
    refreshLists: document.getElementById("refreshListsBtn"), lCont: document.getElementById("listsContainer"),
    lStatus: document.getElementById("listStatus"), lFormStatus: document.getElementById("listFormStatus"),
    powerBtn: document.getElementById("powerBtn"),
    langBtn: document.getElementById("langBtn")
  };

  let currentRules = [];
  let currentDirect = [];
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

  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      panels.forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      panels[i].classList.add("active");
    });
  });

  function isIpHost(h) {
    h = String(h || "").replace(/^\*\./, "");
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || h.indexOf(":") >= 0;
  }
  function hasNonLatin(s) {
    return /[^\x00-\x7F]/.test(String(s || ""));
  }
  function stripNonLatin(s) {
    return String(s || "").replace(/[^\x00-\x7F]/g, "");
  }
  function isAcceptableHost(h) {
    h = String(h || "");
    if (!h || /\s/.test(h) || hasNonLatin(h)) return false;
    if (isIpHost(h)) return true;
    if (!/^[a-z0-9.:\[\]-]+$/i.test(h)) return false;
    return h.indexOf(".") >= 0 && h.indexOf("..") < 0;
  }
  function normalize(v) {
    const trimmed = String(v || "").trim();
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
  function hostOfRule(rule) { return normalize(rule).replace(/^\*\./, ""); }
  function wildcardRule(host) {
    const h = hostOfRule(host);
    if (!h) return "";
    return isIpHost(h) ? h : "*." + h;
  }
  function toGuiRule(v) { return normalize(v); }
  function displayRuleForHost(host) {
    const h = hostOfRule(host);
    if (!h) return "";
    return isIpHost(h) ? h : wildcardRule(h);
  }
  function matches(h, r) {
    const hh = hostOfRule(h), rr = normalize(r);
    if (!hh || !rr) return false;
    if (rr.startsWith("*.")) {
      const b = rr.slice(2);
      return hh === b || hh.endsWith("." + b);
    }
    return hh === rr;
  }
  function hasIn(list, rule) {
    const n = normalize(rule);
    return !!n && list.some(r => normalize(r) === n);
  }
  function hasFullIn(list, host) {
    const h = hostOfRule(host);
    if (!h) return false;
    if (hasIn(list, h)) return true;
    return !isIpHost(h) && hasIn(list, "*." + h);
  }
  function hasUserRule(rule) { return hasIn(currentRules, rule) || hasIn(currentDirect, rule); }
  function isDirectRule(rule) { return hasIn(currentDirect, rule); }
  function existingUserRule(host) {
    const typed = normalize(host);
    if (typed && hasUserRule(typed)) return typed;
    const h = hostOfRule(host);
    if (!h) return "";
    if (!isIpHost(h) && hasUserRule("*." + h)) return "*." + h;
    if (hasUserRule(h)) return h;
    return "";
  }
  function removeUserRule(rule) {
    const n = normalize(rule);
    currentRules = currentRules.filter(i => normalize(i) !== n);
    currentDirect = currentDirect.filter(i => normalize(i) !== n);
  }
  function removeUserRulesForHost(host) {
    const h = hostOfRule(host);
    if (!h) return;
    removeUserRule(h);
    if (!isIpHost(h)) removeUserRule("*." + h);
  }
  function setUserRule(rule, action) {
    const n = normalize(rule);
    if (!n) return;
    removeUserRulesForHost(n);
    if (action === "direct") currentDirect.push(n);
    else currentRules.push(n);
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
  function coveringParent(host, proxyList, directList) {
    const hostN = hostOfRule(host);
    let bestLen = -1, bestAct = "", bestRule = "";
    function consider(list, act) {
      (list || []).forEach(r => {
        if (hostOfRule(r) === hostN || !matches(host, r)) return;
        const len = hostOfRule(r).length;
        if (len > bestLen || (len === bestLen && act === "direct")) {
          bestLen = len;
          bestAct = act;
          bestRule = normalize(r);
        }
      });
    }
    consider(proxyList || currentRules, "proxy");
    consider(directList || currentDirect, "direct");
    return { act: bestAct, rule: bestRule };
  }
  function coveringParentAction(host, proxyList, directList) {
    return coveringParent(host, proxyList, directList).act;
  }
  function currentTargetRule() {
    if (scopeMode === "apex" && pageApex) return wildcardRule(pageApex);
    return displayRuleForHost(pageHost || els.domainInput.value);
  }
  let coverSeq = 0;
  let lastCover = { host: "", listed: false, listedParent: false, listedParentRule: "", listName: "" };
  let domainCovers = {};
  async function requestCoverInfo(host) {
    try {
      return await browser.runtime.sendMessage({ action: "coverInfo", host }) || { listed: false, listedParent: false, listedParentRule: "", listName: "" };
    } catch (e) {
      return { listed: false, listedParent: false, listedParentRule: "", listName: "" };
    }
  }
  async function requestCoverMany(hosts) {
    try {
      const res = await browser.runtime.sendMessage({ action: "coverInfoMany", hosts });
      return (res && res.covers) || {};
    } catch (e) {
      return {};
    }
  }
  function refreshListCover() {
    const host = hostOfRule(els.domainInput.value);
    if (!host) {
      lastCover = { host: "", listed: false, listedParent: false, listedParentRule: "", listName: "" };
      paintStatusIcon();
      return;
    }
    const seq = ++coverSeq;
    requestCoverInfo(host).then(info => {
      if (seq !== coverSeq) return;
      lastCover = {
        host,
        listed: !!(info && info.listed),
        listedParent: !!(info && info.listedParent),
        listedParentRule: (info && info.listedParentRule) || "",
        listName: (info && info.listName) || ""
      };
      paintStatusIcon();
    });
  }
  function refreshScopeUI() {
    const hasChoice = !!(pageHost && pageApex && pageHost !== pageApex && !isIpHost(pageHost));
    if (!hasChoice) scopeMode = "host";
    els.scopeApex.hidden = !hasChoice;
    els.scopeApex.disabled = !hasChoice;
    if (els.domainScope) els.domainScope.style.display = hasChoice ? "flex" : "none";
    els.scopeHost.classList.toggle("active", scopeMode === "host");
    els.scopeApex.classList.toggle("active", hasChoice && scopeMode === "apex");
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
  const SVGS = {
    check: '<svg class="mark-main" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4.5 12.5l5.2 5.3L19.5 6.8" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    x: '<svg class="mark-main" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="2.8" stroke-linecap="round"/></svg>',
    dot: '<svg class="mark-main" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="6.4" fill="currentColor"/></svg>',
    list: '<svg class="mark-list" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M4.5 8.4l7.5-3.4 7.5 3.4-7.5 3.4-7.5-3.4z" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M4.5 12.4l7.5 3.4 7.5-3.4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M4.5 16.4l7.5 3.4 7.5-3.4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    refresh: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-2.6-6.4"/><polyline points="21 3 21 9 15 9"/></svg>',
    edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>'
  };

  function escapeHtml(s) {
    return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  const STATUS = {
    none: { get title() { return I18n.t("status_none"); }, tone: "none", icons: ["x"] },
    proxyFull: { get title() { return I18n.t("status_proxy_full"); }, tone: "proxy", icons: ["check"] },
    directFull: { get title() { return I18n.t("status_direct_full"); }, tone: "direct", icons: ["check"] },
    proxyApex: { get title() { return I18n.t("status_proxy_apex"); }, tone: "proxy", icons: ["dot"] },
    directApex: { get title() { return I18n.t("status_direct_apex"); }, tone: "direct", icons: ["dot"] },
    listFull: { get title() { return I18n.t("status_list_full"); }, tone: "proxy", icons: ["check", "list"] },
    listApex: { get title() { return I18n.t("status_list_apex"); }, tone: "proxy", icons: ["dot", "list"] }
  };
  function coverOf(host, covers) {
    if (!host || !covers) return null;
    return covers[host] || covers[normalize(host)] || null;
  }
  function collectOverlayRules() {
    const proxy = [];
    const direct = [];
    if (!els.domainsList) return { proxy, direct };
    els.domainsList.querySelectorAll("input.domain-pick").forEach(cb => {
      if (!cb.checked) return;
      const rule = cb.dataset.rule;
      if (!rule) return;
      const line = cb.closest(".domain-line");
      const mode = line && line.querySelector("input.mode-direct");
      if (mode && mode.checked) direct.push(rule);
      else proxy.push(rule);
    });
    return { proxy, direct };
  }
  function statusForHost(host, covers, overlay) {
    if (!host) return STATUS.none;
    const proxy = overlay && Array.isArray(overlay.proxy) ? overlay.proxy : currentRules;
    const direct = overlay && Array.isArray(overlay.direct) ? overlay.direct : currentDirect;
    if (hasFullIn(proxy, host)) return STATUS.proxyFull;
    if (hasFullIn(direct, host)) return STATUS.directFull;
    const parentAct = coveringParentAction(host, proxy, direct);
    if (parentAct === "direct") return STATUS.directApex;
    if (parentAct === "proxy") return STATUS.proxyApex;
    const info = coverOf(host, covers);
    const listed = info ? info.listed : (lastCover.host === host && lastCover.listed);
    const listedParent = info ? info.listedParent : (lastCover.host === host && lastCover.listedParent);
    if (listed) return listedParent ? STATUS.listApex : STATUS.listFull;
    return STATUS.none;
  }
  function paintStatusEl(el, st, title) {
    if (!el || !st) return;
    const icons = (st.icons || []).map(name => SVGS[name] || "").join("");
    el.innerHTML = `<span class="status-mark ${st.tone || ""}">${icons}</span>`;
    const label = title || st.title;
    el.title = label;
    el.setAttribute("aria-label", label);
  }
  function paintHostStatus(el, host, covers, overlay) {
    const st = statusForHost(host, covers, overlay);
    const cap = statusCaptionFor(host, covers, overlay);
    paintStatusEl(el, st, cap.text || st.title);
  }
  function coverInfoOf(host, covers) {
    return coverOf(host, covers) || (lastCover.host === host ? lastCover : null);
  }
  function statusCaptionFor(host, covers, overlay) {
    if (!host) return { text: "", kind: "" };
    const proxy = overlay && Array.isArray(overlay.proxy) ? overlay.proxy : currentRules;
    const direct = overlay && Array.isArray(overlay.direct) ? overlay.direct : currentDirect;
    const st = statusForHost(host, covers, overlay);
    if (st === STATUS.proxyFull) return { text: "", kind: "proxy" };
    if (st === STATUS.directFull) return { text: "", kind: "direct" };
    if (st === STATUS.proxyApex) {
      const p = coveringParent(host, proxy, direct);
      return { text: p.rule ? I18n.t("status_proxied_by_rule", { rule: p.rule }) : I18n.t("status_proxy_apex"), kind: "proxy" };
    }
    if (st === STATUS.directApex) {
      const p = coveringParent(host, proxy, direct);
      return { text: p.rule ? I18n.t("status_direct_by_rule", { rule: p.rule }) : I18n.t("status_direct_apex"), kind: "direct" };
    }
    if (st === STATUS.listFull) {
      const info = coverInfoOf(host, covers);
      const name = info && info.listName;
      return { text: name ? I18n.t("status_proxied_by_list", { name }) : I18n.t("status_list_full"), kind: "proxy" };
    }
    if (st === STATUS.listApex) {
      const info = coverInfoOf(host, covers);
      const rule = info && info.listedParentRule;
      const name = info && info.listName;
      if (name && rule) return { text: I18n.t("status_proxied_by_list_rule", { name, rule }), kind: "proxy" };
      if (name) return { text: I18n.t("status_proxied_by_list", { name }), kind: "proxy" };
      if (rule) return { text: I18n.t("status_proxied_by_rule", { rule }), kind: "proxy" };
      return { text: I18n.t("status_list_full"), kind: "proxy" };
    }
    if (st === STATUS.none) return { text: I18n.t("status_none"), kind: "none" };
    return { text: "", kind: "" };
  }
  function paintStatusIcon() {
    const host = hostOfRule(els.domainInput.value);
    paintHostStatus(els.statusIcon, host, null, null);
  }
  function syncOpenDomainLine(rule) {
    if (!domainsPanelOpen) return;
    const host = hostOfRule(rule);
    els.domainsList.querySelectorAll("input.domain-pick").forEach(box => {
      if (hostOfRule(box.dataset.rule) !== host) return;
      const existing = existingUserRule(box.dataset.rule);
      box.checked = !!existing;
      const line = box.closest(".domain-line");
      const mode = line && line.querySelector("input.mode-direct");
      if (mode) mode.checked = !!(existing && isDirectRule(existing));
      if (line) line.classList.toggle("picked", box.checked);
    });
    const overlay = collectOverlayRules();
    els.domainsList.querySelectorAll(".domain-line").forEach(line => {
      const pick = line.querySelector("input.domain-pick");
      const mark = line.querySelector(".mini-status");
      if (!pick) return;
      line.classList.toggle("picked", !!pick.checked);
      paintHostStatus(mark, hostOfRule(pick.dataset.rule), domainCovers, overlay);
    });
  }
  function refreshIcon() {
    paintStatusIcon();
    refreshToggleBtn();
    refreshListCover();
  }
  function refreshToggleBtn() {
    const raw = els.domainInput.value;
    const trimmed = raw.trim();
    const rule = toGuiRule(raw);
    const existing = existingUserRule(rule);
    const inList = !!existing;
    const direct = inList && isDirectRule(existing);
    els.toggleRule.textContent = inList ? I18n.t("btn_remove_rule") : I18n.t("btn_to_rules");
    els.toggleRule.className = inList ? "danger" : "primary";
    els.toggleRule.disabled = !rule;
    els.domainActionRow.classList.toggle("has-rule", inList);
    els.domainMode.classList.toggle("show", inList);
    els.domainMode.classList.toggle("on", direct);
    els.domainDirect.checked = direct;
    const hintSpace = I18n.t("hint_no_spaces");
    const hintLatin = I18n.t("hint_latin_only");
    const hintDot = I18n.t("hint_dot_required");
    const cur = els.rulesStatus.textContent;
    if (trimmed && !rule) {
      els.rulesStatus.style.color = "#ff6b6b";
      els.rulesStatus.textContent = /\s/.test(trimmed) ? hintSpace : hasNonLatin(trimmed) ? hintLatin : hintDot;
    } else if (cur === hintSpace || cur === hintLatin || cur === hintDot) {
      els.rulesStatus.textContent = "";
    }
  }
  function flash(el, t, c = "#57f287") {
    el.style.color = c; el.textContent = t;
    setTimeout(() => { if (el.textContent === t) el.textContent = ""; }, 2000);
  }
  function foldSearch(s) {
    return String(s || "").toLowerCase().replace(/\s+/g, "");
  }
  function applySearchFilter(container, itemsSel, query, emptyEl, emptyDefault) {
    if (!container) return 0;
    const q = foldSearch(query);
    let total = 0, shown = 0;
    container.querySelectorAll(itemsSel).forEach(el => {
      total++;
      const hay = el.getAttribute("data-search") || el.textContent || "";
      const ok = !q || foldSearch(hay).indexOf(q) >= 0;
      el.style.display = ok ? "" : "none";
      if (ok) shown++;
    });
    if (emptyEl) {
      if (!total) {
        emptyEl.textContent = emptyDefault;
        emptyEl.style.display = "block";
      } else if (!shown) {
        emptyEl.textContent = I18n.t("empty_generic");
        emptyEl.style.display = "block";
      } else {
        emptyEl.style.display = "none";
      }
    }
    return shown;
  }
  function filterDomainsList() {
    applySearchFilter(els.domainsList, ".domain-item", els.domainsSearch && els.domainsSearch.value, els.domainsEmpty, I18n.t("empty_domains"));
  }
  function filterProxies() {
    applySearchFilter(els.pCont, ".list-card", els.proxySearch && els.proxySearch.value, els.proxyEmpty, I18n.t("empty_proxies"));
  }
  function filterLists() {
    applySearchFilter(els.lCont, ".list-card", els.listsSearch && els.listsSearch.value, els.listsEmpty, I18n.t("empty_lists"));
  }

  async function checkAutoReload(rule) {
    if (!activeTab || activeTab.id == null || !isWebTab(activeTab)) return;
    try {
      const url = new URL(activeTab.url);
      if (matches(url.hostname, rule)) await browser.tabs.reload(activeTab.id);
    } catch (_) {}
  }

  async function saveRules() {
    await browser.storage.local.set({ proxyRules: currentRules, directRules: currentDirect });
  }

  async function fetchTabDomains() {
    const set = new Set();
    if (isWebTab(activeTab)) {
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

  function renderDomainsList(domains, covers) {
    els.domainsList.textContent = "";
    const uniq = [];
    (domains || []).forEach(d => {
      const h = String(d || "").trim().toLowerCase();
      if (h && uniq.indexOf(h) < 0) uniq.push(h);
    });
    uniq.sort();
    if (!uniq.length) {
      filterDomainsList();
      return;
    }
    covers = covers || {};
    function refreshDomainLine(line, overlay) {
      const pick = line.querySelector("input.domain-pick");
      const mark = line.querySelector(".mini-status");
      if (!pick) return;
      const picked = !!pick.checked;
      line.classList.toggle("picked", picked);
      const host = hostOfRule(pick.dataset.rule);
      paintHostStatus(mark, host, covers, overlay || collectOverlayRules());
    }
    function refreshAllDomainLines() {
      const overlay = collectOverlayRules();
      els.domainsList.querySelectorAll(".domain-line").forEach(line => refreshDomainLine(line, overlay));
    }
    function syncApex(apex, checked, direct) {
      els.domainsList.querySelectorAll("input.domain-pick").forEach(box => {
        if (box.dataset.kind !== "apex" || box.dataset.apex !== apex) return;
        box.checked = checked;
        const line = box.closest(".domain-line");
        const mode = line && line.querySelector("input.mode-direct");
        if (mode && direct != null) mode.checked = direct;
      });
      refreshAllDomainLines();
    }
    function appendLine(parent, rule, kind, apex, bold) {
      const existing = existingUserRule(rule);
      const isDirect = existing && isDirectRule(existing);
      const line = document.createElement("div");
      line.className = `domain-line${existing ? " picked" : ""}`;
      line.innerHTML = `
        <input type="checkbox" class="domain-pick" data-rule="${escapeHtml(rule)}" data-kind="${kind}" data-apex="${escapeHtml(apex)}" ${existing ? "checked" : ""}>
        <span class="mini-status"></span>
        <span class="${bold ? "domain-name" : "domain-apex"}" title="${escapeHtml(rule)}">${escapeHtml(rule)}</span>
        <label class="mode-wrap" title="${escapeHtml(I18n.t("mode_proxy_direct"))}">
          <span class="switch mode-switch">
            <input type="checkbox" class="mode-direct" ${isDirect ? "checked" : ""}>
            <span class="switch-ui"></span>
          </span>
        </label>
      `;

      const cb = line.querySelector("input.domain-pick");
      const mode = line.querySelector("input.mode-direct");
      const text = line.querySelector(bold ? ".domain-name" : ".domain-apex");
      const modeWrap = line.querySelector(".mode-wrap");

      modeWrap.addEventListener("click", e => e.stopPropagation());
      text.addEventListener("click", () => { cb.checked = !cb.checked; cb.dispatchEvent(new Event("change")); });

      const onToggle = () => {
        if (kind === "apex") syncApex(apex, cb.checked, mode.checked);
        else refreshDomainLine(line);
      };
      cb.addEventListener("change", onToggle);
      mode.addEventListener("change", onToggle);

      refreshDomainLine(line);
      parent.appendChild(line);
    }
    const pageHostKey = (pageHost || "").toLowerCase();
    const pageApexKey = (pageApex || (pageHostKey ? apexDomain(pageHostKey) || pageHostKey : "")).toLowerCase();
    const groups = new Map();
    uniq.forEach(host => {
      const apex = apexDomain(host) || host;
      if (!groups.has(apex)) groups.set(apex, []);
      const list = groups.get(apex);
      if (list.indexOf(host) < 0) list.push(host);
    });
    Array.from(groups.keys()).sort((a, b) => {
      const aPage = pageApexKey && a === pageApexKey;
      const bPage = pageApexKey && b === pageApexKey;
      if (aPage !== bPage) return aPage ? -1 : 1;
      return a.localeCompare(b);
    }).forEach(apex => {
      const hosts = groups.get(apex).slice().sort((a, b) => {
        const aPage = pageHostKey && a === pageHostKey;
        const bPage = pageHostKey && b === pageHostKey;
        if (aPage !== bPage) return aPage ? -1 : 1;
        return a.localeCompare(b);
      });
      const item = document.createElement("div");
      item.className = "domain-item";
      const searchBits = [apex];
      if (isIpHost(apex)) {
        appendLine(item, toGuiRule(apex), "apex", apex, true);
      } else {
        appendLine(item, wildcardRule(apex), "apex", apex, true);
        hosts.forEach(host => {
          if (host === apex) return;
          searchBits.push(host);
          appendLine(item, wildcardRule(host), "host", apex, false);
        });
      }
      item.dataset.search = searchBits.join(" ");
      els.domainsList.appendChild(item);
    });
    refreshAllDomainLines();
    filterDomainsList();
  }

  function closeDomainsPanel() {
    domainsPanelOpen = false;
    els.domainsPanel.classList.remove("open");
    els.viewDomains.classList.remove("open");
    els.domainsList.textContent = "";
    if (els.domainsSearch) els.domainsSearch.value = "";
  }

  function applyDomainDraft() {
    let added = 0, removed = 0, changed = 0;
    const listed = new Map();
    els.domainsList.querySelectorAll("input.domain-pick").forEach(cb => {
      const rule = cb.dataset.rule;
      if (!rule) return;
      const n = hostOfRule(rule) || normalize(rule);
      const line = cb.closest(".domain-line");
      const mode = line && line.querySelector("input.mode-direct");
      const direct = !!(mode && mode.checked);
      const prev = listed.get(n);
      listed.set(n, { rule, want: cb.checked || (prev && prev.want), direct: cb.checked ? direct : (prev && prev.direct) });
    });
    listed.forEach(({ rule, want, direct }) => {
      const existing = existingUserRule(rule);
      const act = direct ? "direct" : "proxy";
      if (want) {
        const wasDirect = existing && isDirectRule(existing);
        if (!existing) { setUserRule(rule, act); added++; }
        else if (wasDirect !== !!direct || normalize(existing) !== normalize(rule)) {
          setUserRule(rule, act);
          changed++;
        }
      } else if (existing) {
        removeUserRulesForHost(rule);
        removed++;
      }
    });
    return { added, removed, changed };
  }

  async function reloadActiveTab() {
    if (activeTab && activeTab.id != null && isWebTab(activeTab)) {
      try { await browser.tabs.reload(activeTab.id); } catch (_) {}
    }
  }

  async function refreshDomainsPanel() {
    if (!domainsPanelOpen) return;
    const domains = await fetchTabDomains();
    const hosts = [];
    (domains || []).forEach(d => {
      const h = String(d || "").trim().toLowerCase();
      if (!h) return;
      hosts.push(h);
      const a = apexDomain(h);
      if (a && a !== h) hosts.push(a);
    });
    domainCovers = await requestCoverMany(hosts);
    renderDomainsList(domains, domainCovers);
  }

  function pluralRu(n, one, few, many) {
    n = Math.abs(Number(n)) || 0;
    const n10 = n % 10;
    const n100 = n % 100;
    if (n10 === 1 && n100 !== 11) return one;
    if (n10 >= 2 && n10 <= 4 && (n100 < 12 || n100 > 14)) return few;
    return many;
  }
  function formatListUpdated(ts) {
    const n = Number(ts);
    if (!(n > 0)) return I18n.t("updated_never");
    const d = new Date(n);
    const pad = v => String(v).padStart(2, "0");
    return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }


  function proxyTypeLabel(t) {
    if (t === "http") return "HTTP";
    if (t === "https") return "HTTPS";
    return "SOCKS5";
  }

  function proxyKey(p) {
    const host = String(p.host || "").trim().toLowerCase();
    const port = Number(p.port) || 0;
    const user = String(p.username || "");
    const pass = String(p.password || "");
    return `${host}|${port}|${user}|${pass}`;
  }

  function proxyAddress(p) {
    const host = String((p && p.host) || "").trim();
    const port = Number(p && p.port);
    if (!host) return "";
    return port > 0 ? `${host}:${port}` : host;
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
    const label = !hasConfiguredProxy() ? I18n.t("power_setup") : (on ? I18n.t("power_off") : I18n.t("power_on"));
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
    currentProxies.forEach(p => {
      const card = document.createElement("div");
      card.className = "list-card";
      const name = String(p.name || "").trim();
      const addr = proxyAddress(p);
      card.dataset.search = [name, addr, p.host || ""].filter(Boolean).join(" ");
      const metaBits = [proxyTypeLabel(p.type)];
      if (p.username) metaBits.push(p.username);

      card.innerHTML = `
        <div class="list-card-body">
          ${name ? `<div class="list-card-title" title="${escapeHtml(name)}">${escapeHtml(name)}</div>` : ""}
          <div class="${name ? "list-card-url" : "list-card-title"}" title="${escapeHtml(addr)}">${escapeHtml(addr)}</div>
          <div class="list-card-meta">${escapeHtml(metaBits.join(" · "))}</div>
        </div>
        <div class="list-card-side">
          <label class="switch" title="${p.enabled ? escapeHtml(I18n.t("proxy_active")) : escapeHtml(I18n.t("proxy_inactive"))}">
            <input type="checkbox" ${p.enabled ? "checked" : ""}>
            <span class="switch-ui"></span>
          </label>
          <button type="button" class="btn-edit" title="${escapeHtml(I18n.t("btn_edit"))}" aria-label="${escapeHtml(I18n.t("btn_edit"))}">${SVGS.edit}</button>
        </div>
      `;

      const chk = card.querySelector(".switch input");
      chk.addEventListener("change", async () => {
        if (!chk.checked) {
          chk.checked = true;
          return;
        }
        await persistProxies(currentProxies.map(item => Object.assign({}, item, { enabled: item.id === p.id })));
        flash(els.pStatus, I18n.t("msg_active_saved"));
      });
      card.querySelector(".btn-edit").addEventListener("click", () => openProxyForm(p));
      els.pCont.appendChild(card);
    });
    filterProxies();
  }

  function showProxyMain() {
    editingProxyId = null;
    els.proxyForm.style.display = "none";
    els.proxyMain.style.display = "flex";
    renderProxies();
  }

  function resetProxyForm() {
    els.pName.value = "";
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
      els.pName.value = item.name || "";
      els.pType.value = item.type === "http" || item.type === "https" ? item.type : "socks";
      els.pHost.value = item.host || "";
      els.pPort.value = item.port || "";
      els.pUser.value = item.username || "";
      els.pPass.value = item.password || "";
      els.saveProxy.textContent = I18n.t("btn_save");
      els.deleteProxy.style.display = "";
    } else {
      editingProxyId = null;
      resetProxyForm();
      els.saveProxy.textContent = I18n.t("btn_save");
      els.deleteProxy.style.display = "none";
    }
  }

  function collectProxyForm() {
    return {
      name: els.pName.value.trim(),
      type: els.pType.value,
      host: els.pHost.value.trim(),
      port: Number(els.pPort.value),
      username: els.pUser.value.trim(),
      password: els.pPass.value.trim()
    };
  }

  function renderLists() {
    els.lCont.textContent = "";
    currentLists.forEach(l => {
      const card = document.createElement("div");
      card.className = "list-card";
      const name = String(l.name || "").trim();
      const url = String(l.url || "");
      card.dataset.search = [name, url].filter(Boolean).join(" ");
      const fmt = l.format === "pac" ? "PAC" : "txt";
      const domains = l.domainCount || (l.domains || []).length || 0;
      const ips = l.ipCount || (l.ips || []).length || 0;
      const domLabel = I18n.getLang() === "ru"
        ? pluralRu(domains, "домен", "домена", "доменов")
        : (domains === 1 ? "domain" : "domains");
      const metaText = `${fmt} · ${domains} ${domLabel} / ${ips} IP`;
      const updatedText = `${I18n.t("lbl_updated")}: ${formatListUpdated(l.updatedAt)}`;

      card.innerHTML = `
        <div class="list-card-body">
          ${name ? `<div class="list-card-title" title="${escapeHtml(name)}">${escapeHtml(name)}</div>` : ""}
          <div class="${name ? "list-card-url" : "list-card-title"}" title="${escapeHtml(url)}">${escapeHtml(url)}</div>
          <div class="list-card-meta">${escapeHtml(metaText)}</div>
          <div class="list-card-updated">${escapeHtml(updatedText)}</div>
          ${l.updateError ? `<div class="list-card-error" title="${escapeHtml(l.updateError)}">${escapeHtml(l.updateError)}</div>` : ""}
        </div>
        <div class="list-card-actions">
          <button type="button" class="btn-refresh" title="${escapeHtml(I18n.t("btn_refresh"))}" aria-label="${escapeHtml(I18n.t("btn_refresh"))}">${SVGS.refresh}</button>
          <button type="button" class="btn-edit" title="${escapeHtml(I18n.t("btn_edit"))}" aria-label="${escapeHtml(I18n.t("btn_edit"))}">${SVGS.edit}</button>
        </div>
      `;

      const refreshBtn = card.querySelector(".btn-refresh");
      refreshBtn.addEventListener("click", () => refreshOneList(l.id, refreshBtn));
      card.querySelector(".btn-edit").addEventListener("click", () => openListForm(l));
      els.lCont.appendChild(card);
    });
    filterLists();
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
      els.lInterval.value = String(Number(item.intervalHours) > 0 ? Number(item.intervalHours) : 12);
      els.lViaProxy.checked = !!item.viaProxy;
      els.saveList.textContent = I18n.t("btn_save");
      els.deleteList.style.display = "";
    } else {
      editingListId = null;
      resetListForm();
      els.saveList.textContent = I18n.t("btn_save");
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
      intervalHours: hours,
      viaProxy: !!els.lViaProxy.checked
    };
  }

  async function sendListMessage(payload) {
    return Promise.race([
      browser.runtime.sendMessage(payload),
      new Promise((_, reject) => setTimeout(() => reject(new Error(I18n.t("msg_timeout"))), 60000))
    ]);
  }

  async function refreshOneList(id, btn) {
    if (btn) { btn.disabled = true; btn.classList.add("busy"); }
    try {
      const res = await sendListMessage({ action: "refreshList", id });
      if (res && res.success) flash(els.lStatus, I18n.t("msg_updated"));
      else flash(els.lStatus, (res && res.error) ? String(res.error).slice(0, 180) : I18n.t("msg_update_error"), "#ff6b6b");
    } catch (e) {
      flash(els.lStatus, String(e.message || e).slice(0, 180), "#ff6b6b");
    } finally {
      if (btn) { btn.disabled = false; btn.classList.remove("busy"); }
    }
  }

  async function loadState() {
    const res = await browser.storage.local.get(["proxyConfig", "proxyServers", "proxyRules", "directRules", "proxyLists", "extensionEnabled"]);
    currentRules = Array.isArray(res.proxyRules) ? res.proxyRules : [];
    currentDirect = Array.isArray(res.directRules) ? res.directRules : [];
    currentLists = Array.isArray(res.proxyLists) ? res.proxyLists : [];
    currentProxies = Array.isArray(res.proxyServers) ? res.proxyServers : [];
    extensionEnabled = !!res.extensionEnabled && hasConfiguredProxy();
    updateLangBtn();
    renderProxies();
    refreshPowerBtn();
    renderLists();
    try {
      const tab = await queryActiveTab();
      if (tab && isWebTab(tab)) {
        activeTab = tab;
        const host = new URL(activeTab.url).hostname;
        if (host) {
          pageHost = normalize(host).replace(/^\*\./, "");
          pageApex = apexDomain(pageHost);
          scopeMode = "host";
          els.domainInput.value = displayRuleForHost(pageHost);
        }
      }
    } catch (_) {}
    refreshScopeUI();
    refreshIcon();
  }

  els.showAddProxy.addEventListener("click", () => openProxyForm(null));
  els.cancelProxy.addEventListener("click", () => showProxyMain());

  els.saveProxy.addEventListener("click", async () => {
    const form = collectProxyForm();
    if (!form.host || !(form.port > 0 && form.port < 65536)) {
      return flash(els.pFormStatus, I18n.t("msg_fill_fields"), "#ff6b6b");
    }
    const dup = currentProxies.find(p => proxyKey(p) === proxyKey(form) && p.id !== editingProxyId);
    if (dup) return flash(els.pFormStatus, I18n.t("msg_proxy_exists"), "#ff6b6b");
    if (editingProxyId != null) {
      const next = currentProxies.map(p => p.id === editingProxyId ? Object.assign({}, p, form) : p);
      await persistProxies(next);
      flash(els.pStatus, I18n.t("msg_proxy_saved"));
    } else {
      const item = Object.assign({ id: Date.now(), enabled: !currentProxies.length }, form);
      await persistProxies(currentProxies.concat(item));
      flash(els.pStatus, I18n.t("msg_proxy_added"));
    }
    showProxyMain();
  });

  els.deleteProxy.addEventListener("click", async () => {
    if (editingProxyId == null) return;
    await persistProxies(currentProxies.filter(p => p.id !== editingProxyId));
    flash(els.pStatus, I18n.t("msg_proxy_deleted"));
    showProxyMain();
  });

  els.toggleRule.addEventListener("click", async () => {
    const raw = els.domainInput.value;
    const trimmed = raw.trim();
    const rule = toGuiRule(raw);
    if (!rule) {
      const msg = !trimmed ? I18n.t("hint_empty_rule") : /\s/.test(trimmed) ? I18n.t("hint_no_spaces") : hasNonLatin(trimmed) ? I18n.t("hint_latin_only") : I18n.t("hint_dot_required");
      return flash(els.rulesStatus, msg, "#ff6b6b");
    }
    const existing = existingUserRule(rule);
    els.domainInput.value = existing || rule;
    if (existing) {
      removeUserRulesForHost(existing);
      await saveRules();
      refreshIcon();
      flash(els.rulesStatus, I18n.t("msg_deleted"));
    } else {
      setUserRule(rule, "proxy");
      await saveRules();
      refreshIcon();
      flash(els.rulesStatus, I18n.t("msg_rule_added"));
    }
    syncOpenDomainLine(existing || rule);
    checkAutoReload(existing || rule);
  });

  els.domainDirect.addEventListener("change", async () => {
    const typed = toGuiRule(els.domainInput.value);
    const existing = existingUserRule(typed);
    if (!typed || !existing) {
      els.domainDirect.checked = false;
      return;
    }
    els.domainInput.value = existing;
    setUserRule(existing, els.domainDirect.checked ? "direct" : "proxy");
    await saveRules();
    refreshIcon();
    flash(els.rulesStatus, els.domainDirect.checked ? I18n.t("rule_direct") : I18n.t("rule_proxy"));
    syncOpenDomainLine(existing);
    checkAutoReload(existing);
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
    const { added, removed, changed } = applyDomainDraft();
    if (added || removed || changed) {
      await saveRules();
      const parts = [];
      if (added) parts.push(I18n.t("msg_added", { count: added }));
      if (removed) parts.push(I18n.t("msg_removed", { count: removed }));
      if (changed && !added && !removed) parts.push(I18n.t("msg_saved"));
      flash(els.rulesStatus, parts.join(", ") || I18n.t("msg_saved"));
    }
    const shown = existingUserRule(els.domainInput.value);
    if (shown) els.domainInput.value = shown;
    refreshIcon();
    closeDomainsPanel();
    if (added || removed || changed) await reloadActiveTab();
  });
  els.cancelDomains.addEventListener("click", () => closeDomainsPanel());
  if (els.domainsSearch) els.domainsSearch.addEventListener("input", filterDomainsList);
  if (els.proxySearch) els.proxySearch.addEventListener("input", filterProxies);
  if (els.listsSearch) els.listsSearch.addEventListener("input", filterLists);

  els.showAddList.addEventListener("click", () => openListForm(null));
  els.cancelList.addEventListener("click", () => showListsMain());

  els.saveList.addEventListener("click", async () => {
    const form = collectListForm();
    if (!form.url.startsWith("http")) return flash(els.lFormStatus, I18n.t("msg_invalid_url"), "#ff6b6b");
    const dup = currentLists.find(l => canonListUrl(l.url) === canonListUrl(form.url) && l.id !== editingListId);
    if (dup) return flash(els.lFormStatus, I18n.t("msg_list_exists"), "#ff6b6b");
    els.saveList.disabled = true;
    els.saveList.classList.add("busy");
    els.saveList.textContent = I18n.t("btn_saving");
    try {
      const existing = editingListId != null ? currentLists.find(l => l.id === editingListId) : null;
      const urlChanged = existing && canonListUrl(existing.url) !== canonListUrl(form.url);
      const proxyChanged = existing && !!existing.viaProxy !== form.viaProxy;
      const needFetch = !existing || urlChanged || proxyChanged;
      const res = await sendListMessage(needFetch
        ? { action: "fetchList", id: editingListId, url: form.url, name: form.name, intervalHours: form.intervalHours, viaProxy: form.viaProxy }
        : { action: "saveListMeta", id: editingListId, url: form.url, name: form.name, intervalHours: form.intervalHours, viaProxy: form.viaProxy });
      if (res && res.success) {
        flash(els.lStatus, existing ? I18n.t("msg_saved") : I18n.t("msg_list_added"));
        showListsMain();
      } else flash(els.lFormStatus, (res && res.error) ? String(res.error).slice(0, 180) : I18n.t("msg_error"), "#ff6b6b");
    } catch (e) {
      flash(els.lFormStatus, String(e.message || e).slice(0, 180), "#ff6b6b");
    } finally {
      els.saveList.disabled = false;
      els.saveList.classList.remove("busy");
      els.saveList.textContent = I18n.t("btn_save");
    }
  });

  els.deleteList.addEventListener("click", async () => {
    if (editingListId == null) return;
    currentLists = currentLists.filter(x => x.id !== editingListId);
    await browser.storage.local.set({ proxyLists: currentLists });
    flash(els.lStatus, I18n.t("msg_deleted"));
    showListsMain();
  });

  els.refreshLists.addEventListener("click", async () => {
    if (!currentLists.length) return flash(els.lStatus, I18n.t("msg_no_lists"), "#ff6b6b");
    els.refreshLists.disabled = true;
    els.refreshLists.classList.add("busy");
    try {
      const res = await sendListMessage({ action: "refreshLists" });
      if (res && res.success) {
        const failed = Number(res.failed) || 0;
        if (failed) flash(els.lStatus, I18n.t("msg_updated_failed", { updated: res.updated || 0, failed }), "#ff6b6b");
        else flash(els.lStatus, I18n.t("msg_updated_count", { count: res.updated || 0 }));
      }
      else flash(els.lStatus, (res && res.error) ? String(res.error).slice(0, 180) : I18n.t("msg_update_error"), "#ff6b6b");
    } catch (e) {
      flash(els.lStatus, String(e.message || e).slice(0, 180), "#ff6b6b");
    } finally {
      els.refreshLists.disabled = false;
      els.refreshLists.classList.remove("busy");
    }
  });

  els.openList.addEventListener("click", () => {
    const url = browser.runtime.getURL("list.html");
    browser.tabs.create({ url }).finally(() => {
      try { window.close(); } catch (_) {}
    });
  });
  document.querySelectorAll(".footer a[href]").forEach(a => {
    a.addEventListener("click", (e) => {
      e.preventDefault();
      const url = a.href;
      if (!url) return;
      browser.tabs.create({ url }).catch(() => {}).finally(() => {
        try { window.close(); } catch (_) {}
      });
    });
  });
  els.domainInput.addEventListener("input", () => {
    const blockedLatin = hasNonLatin(els.domainInput.value);
    if (blockedLatin) els.domainInput.value = stripNonLatin(els.domainInput.value);
    const h = hostOfRule(els.domainInput.value);
    if (h) {
      pageHost = h;
      pageApex = apexDomain(h);
      if (pageApex && h === pageApex) scopeMode = "host";
    }
    refreshScopeUI();
    refreshIcon();
    if (blockedLatin) {
      els.rulesStatus.style.color = "#ff6b6b";
      els.rulesStatus.textContent = I18n.t("hint_latin_only");
    }
  });

  function updateLangBtn() {
    if (!els.langBtn) return;
    els.langBtn.textContent = I18n.getLang().toUpperCase();
    els.langBtn.title = I18n.t("btn_switch_lang_title");
  }

  if (els.langBtn) {
    els.langBtn.addEventListener("click", async () => {
      const next = I18n.getLang() === "ru" ? "en" : "ru";
      await I18n.setLang(next, browser);
      updateLangBtn();
      renderProxies();
      renderLists();
      refreshPowerBtn();
      refreshToggleBtn();
      refreshIcon();
    });
  }

  els.powerBtn.addEventListener("click", async () => {
    if (!hasConfiguredProxy()) {
      showProxyTab();
      flash(els.pStatus, I18n.t("msg_setup_proxy_first"), "#ff6b6b");
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
    if (c.directRules) {
      currentDirect = c.directRules.newValue || [];
      refreshIcon();
    }
    if (c.proxyLists) {
      currentLists = c.proxyLists.newValue || [];
      renderLists();
      lastCover = { host: "", listed: false, listedParent: false, listedParentRule: "", listName: "" };
      refreshIcon();
    }
    if (c.proxyServers) {
      currentProxies = Array.isArray(c.proxyServers.newValue) ? c.proxyServers.newValue : [];
      renderProxies();
      refreshPowerBtn();
    }
    if (c.extensionEnabled) {
      extensionEnabled = !!c.extensionEnabled.newValue && hasConfiguredProxy();
      refreshPowerBtn();
    }
  });

  await loadState();
});
