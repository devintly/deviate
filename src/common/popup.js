const browser = globalThis.browser || globalThis.chrome;

document.addEventListener("DOMContentLoaded", async () => {
  if (typeof I18n !== "undefined") await I18n.init(browser);

  function ownPageBase() {
    try { return browser.runtime.getURL(""); } catch (_) { return ""; }
  }
  function isWebTab(tab) { return HostRules.isWebTab(tab, ownPageBase()); }
  function isOwnPage(url, base) { return HostRules.isOwnPage(url, base); }

  function getTabWebUrl(tab) {
    if (!tab) return "";
    const url = String(tab.url || "");
    if (url.startsWith("http://") || url.startsWith("https://")) return url;
    const pending = String(tab.pendingUrl || "");
    if (pending.startsWith("http://") || pending.startsWith("https://")) return pending;
    return "";
  }

  function isErrorTab(tab) {
    if (!tab) return false;
    const url = String(tab.url || "");
    return url.startsWith("chrome-error://") || url.startsWith("about:neterror");
  }

  function isEligibleTab(tab) {
    if (!tab) return false;
    if (isOwnPage(tab.url, ownPageBase()) || isOwnPage(tab.pendingUrl, ownPageBase())) return false;
    return !!getTabWebUrl(tab) || isErrorTab(tab);
  }

  async function queryActiveTab() {
    function pickEligible(tabs) {
      if (!Array.isArray(tabs)) return null;
      for (let i = 0; i < tabs.length; i++) {
        const t = tabs[i];
        if (t && isEligibleTab(t)) return t;
      }
      return null;
    }

    try {
      const tabs = await browser.tabs.query({ active: true, lastFocusedWindow: true });
      const tab = pickEligible(tabs);
      if (tab) return tab;
    } catch (_) {}

    try {
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      const tab = pickEligible(tabs);
      if (tab) return tab;
    } catch (_) {}

    try {
      const tabs = await browser.tabs.query({ active: true });
      const tab = pickEligible(tabs);
      if (tab) return tab;
    } catch (_) {}

    return null;
  }


  const tabs = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".panel");
  const els = {
    domainInput: document.getElementById("domainInput"), statusIcon: document.getElementById("statusIcon"),
    mainWildcard: document.getElementById("mainWildcardBtn"),
    toggleRule: document.getElementById("toggleRuleBtn"), viewDomains: document.getElementById("viewDomainsBtn"),
    domainActionRow: document.getElementById("domainActionRow"), domainMode: document.getElementById("domainModeSwitch"),
    domainDirect: document.getElementById("domainDirect"),
    scopeHost: document.getElementById("scopeHostBtn"), scopeApex: document.getElementById("scopeApexBtn"),
    domainScope: document.getElementById("domainScope"),
    domainsPanel: document.getElementById("domainsPanel"), domainsList: document.getElementById("domainsList"),
    domainsSearch: document.getElementById("domainsSearch"), toggleDomainTree: document.getElementById("toggleDomainTreeBtn"),
    domainsEmpty: document.getElementById("domainsEmpty"), saveDomains: document.getElementById("saveDomainsBtn"),
    cancelDomains: document.getElementById("cancelDomainsBtn"),
    rulesStatus: document.getElementById("rulesStatus"), openList: document.getElementById("openListBtn"),
    pName: document.getElementById("proxyName"),
    pType: document.getElementById("proxyType"), pHost: document.getElementById("proxyHost"),
    pPort: document.getElementById("proxyPort"), pUser: document.getElementById("proxyUser"),
    pPass: document.getElementById("proxyPass"), saveProxy: document.getElementById("saveProxyBtn"),
    proxyMain: document.getElementById("proxyMain"), proxyForm: document.getElementById("proxyForm"),
    proxyEmpty: document.getElementById("proxyEmpty"), pCont: document.getElementById("proxyContainer"),
    proxySearch: document.getElementById("proxySearch"),
    showAddProxy: document.getElementById("showAddProxyBtn"), deleteProxy: document.getElementById("deleteProxyBtn"),
    pingProxies: document.getElementById("pingProxiesBtn"),
    cancelProxy: document.getElementById("cancelProxyBtn"),
    listsMain: document.getElementById("listsMain"), listsForm: document.getElementById("listsForm"),
    listsEmpty: document.getElementById("listsEmpty"), listsSearch: document.getElementById("listsSearch"),
    lName: document.getElementById("listName"), lUrl: document.getElementById("listUrl"),
    lInterval: document.getElementById("listInterval"),
    lViaProxy: document.getElementById("listViaProxy"),
    showAddList: document.getElementById("showAddListBtn"), saveList: document.getElementById("saveListBtn"),
    deleteList: document.getElementById("deleteListBtn"), cancelList: document.getElementById("cancelListBtn"),
    refreshLists: document.getElementById("refreshListsBtn"), lCont: document.getElementById("listsContainer"),
    powerBtn: document.getElementById("powerBtn"),
    infoBtn: document.getElementById("infoBtn"),
    infoModal: document.getElementById("infoModal"),
    closeInfoBtn: document.getElementById("closeInfoBtn"),
    infoVersion: document.getElementById("infoVersion"),
    conflictBanner: document.getElementById("conflictBanner"),
    toastContainer: document.getElementById("toastContainer")
  };

  let currentRules = [];
  let currentDirect = [];
  let currentLists = [];
  let currentProxies = [];
  let currentPingResults = {};
  let activeTab = null;
  let domainsPanelOpen = false;
  let showDomainTree = false;
  let loadedTabHosts = new Set();
  let lastFetchedDomains = [];
  let pageHost = "";
  let pageApex = "";
  let scopeMode = "host";
  let editingListId = null;
  let editingProxyId = null;
  let extensionEnabled = false;
  let isConflictBlocked = false;

  function activateTab(index, focus) {
    tabs.forEach((tab, i) => {
      const active = i === index;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.tabIndex = active ? 0 : -1;
      if (panels[i]) panels[i].classList.toggle("active", active);
    });
    if (focus && tabs[index]) tabs[index].focus();
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => activateTab(i, false));
    tab.addEventListener("keydown", e => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
      e.preventDefault();
      const next = e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1
        : (i + (e.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
      activateTab(next, true);
    });
  });

  const isIpHost = HostRules.isIpHost;
  const normalize = HostRules.normalizeRule;
  function hasNonLatin(s) {
    return /[^\x00-\x7F]/.test(String(s || ""));
  }
  function stripNonLatin(s) {
    return String(s || "").replace(/[^\x00-\x7F]/g, "");
  }
  function hostOfRule(rule) { return normalize(rule).replace(/^\*\./, ""); }
  function wildcardRule(host) {
    const h = hostOfRule(host);
    if (!h) return "";
    return isIpHost(h) ? h : "*." + h;
  }
  function displayRuleForHost(host) {
    const h = hostOfRule(host);
    if (!h) return "";
    return h;
  }
  const matches = HostRules.ruleMatchesHost;
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
    const h = hostOfRule(host);
    if (!h) return "";
    if (hasIn(currentRules, h)) return h;
    if (hasIn(currentDirect, h)) return h;
    if (!isIpHost(h)) {
      const w = "*." + h;
      if (hasIn(currentRules, w)) return w;
      if (hasIn(currentDirect, w)) return w;
    }
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
  const apexDomain = HostRules.apexDomain;
  const buildDomainTree = HostRules.buildDomainTree;
  function coveringParent(host, proxyList, directList) {
    const result = HostRules.coveringRule(host, proxyList || currentRules, directList || currentDirect);
    return { act: result.action, rule: result.rule };
  }
  function coveringParentAction(host, proxyList, directList) {
    return coveringParent(host, proxyList, directList).act;
  }
  function effectiveInputRule() {
    const raw = (els.domainInput && els.domainInput.value || "").trim();
    if (!raw) return "";
    const n = normalize(raw);
    if (!n) return "";
    const h = hostOfRule(n) || n;
    if (isIpHost(h)) return h;
    const isWild = els.mainWildcard ? els.mainWildcard.classList.contains("active") : true;
    return isWild ? "*." + h : h;
  }
  function currentTargetRule() {
    if (scopeMode === "apex" && pageApex) {
      const isWild = els.mainWildcard ? els.mainWildcard.classList.contains("active") : true;
      return isWild ? "*." + pageApex : pageApex;
    }
    return effectiveInputRule();
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
      const target = scopeMode === "apex" && pageApex ? pageApex : pageHost;
      if (target) {
        els.domainInput.value = target;
        if (els.mainWildcard && !isIpHost(target)) {
          const existing = existingUserRule(target);
          if (existing) {
            els.mainWildcard.classList.toggle("active", existing.startsWith("*."));
          } else {
            els.mainWildcard.classList.add("active");
          }
        }
      }
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
    edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg>',
    chevron: '<svg class="expander-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 3l5 5-5 5"/></svg>'
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
    if (!els.domainsList) return { proxy: currentRules.slice(), direct: currentDirect.slice() };
    const modalHosts = new Set();
    const addProxy = [];
    const addDirect = [];
    els.domainsList.querySelectorAll(".domain-line").forEach(line => {
      const cb = line.querySelector("input.domain-pick");
      if (!cb) return;
      const host = cb.dataset.host || hostOfRule(cb.dataset.rule);
      if (!host) return;
      modalHosts.add(host);
      if (cb.checked) {
        const wildBtn = line.querySelector(".domain-wildcard-btn");
        const isWild = isIpHost(host) ? false : (wildBtn && wildBtn.classList.contains("active"));
        const rule = isIpHost(host) ? normalize(host) : (isWild ? "*." + host : host);
        const mode = line.querySelector("input.mode-direct");
        if (mode && mode.checked) addDirect.push(rule);
        else addProxy.push(rule);
      }
    });
    const proxy = currentRules.filter(r => !modalHosts.has(hostOfRule(r))).concat(addProxy);
    const direct = currentDirect.filter(r => !modalHosts.has(hostOfRule(r))).concat(addDirect);
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
    const host = hostOfRule(els.domainInput.value) || normalize(els.domainInput.value);
    paintHostStatus(els.statusIcon, host, null, null);
  }
  function syncOpenDomainLine(rule) {
    if (!domainsPanelOpen) return;
    const host = hostOfRule(rule);
    els.domainsList.querySelectorAll("input.domain-pick").forEach(box => {
      const bHost = box.dataset.host || hostOfRule(box.dataset.rule);
      if (bHost !== host) return;
      const existing = existingUserRule(bHost);
      box.checked = !!existing;
      const line = box.closest(".domain-line");
      const mode = line && line.querySelector("input.mode-direct");
      if (mode) mode.checked = !!(existing && isDirectRule(existing));
      const wildBtn = line && line.querySelector(".domain-wildcard-btn");
      if (wildBtn && !isIpHost(bHost)) {
        if (existing) wildBtn.classList.toggle("active", existing.startsWith("*."));
      }
      if (line) line.classList.toggle("picked", box.checked);
    });
    const overlay = collectOverlayRules();
    els.domainsList.querySelectorAll(".domain-line").forEach(line => {
      const pick = line.querySelector("input.domain-pick");
      const mark = line.querySelector(".mini-status");
      if (!pick) return;
      line.classList.toggle("picked", !!pick.checked);
      const h = pick.dataset.host || hostOfRule(pick.dataset.rule);
      paintHostStatus(mark, h, domainCovers, overlay);
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
    const h = hostOfRule(trimmed) || normalize(trimmed);
    const isIp = isIpHost(h);
    if (els.mainWildcard) {
      els.mainWildcard.style.display = isIp || !h ? "none" : "inline-flex";
    }
    const rule = effectiveInputRule();
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
  let activeToast = null;
  let toastHideTimer = null;

  function dismissToast(el) {
    if (!el) return;
    el.classList.remove("toast-in");
    el.classList.add("toast-out");
    setTimeout(() => {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, 250);
  }

  function showToast(text, type = "success") {
    if (!text) return;
    const container = els.toastContainer || document.getElementById("toastContainer");
    if (!container) return;

    if (toastHideTimer) {
      clearTimeout(toastHideTimer);
      toastHideTimer = null;
    }

    if (activeToast) {
      dismissToast(activeToast);
      activeToast = null;
    }

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.textContent = text;
    container.appendChild(toast);
    activeToast = toast;

    void toast.offsetHeight;
    toast.classList.add("toast-in");

    toastHideTimer = setTimeout(() => {
      if (activeToast === toast) {
        activeToast = null;
      }
      dismissToast(toast);
    }, 2200);
  }
  function flash(t, c = "#57f287") {
    const isErr = c === "#ff6b6b" || (typeof c === "string" && (c.includes("da373c") || c.includes("ff6b6b")));
    showToast(t, isErr ? "error" : "success");
  }
  function flashError(err, code, fallbackKey) {
    const errCode = code || (err && err.code) || "";
    const text = String((err && err.message) || err || "").trim();
    flash(errCode || text ? I18n.error(err, errCode) : I18n.t(fallbackKey || "msg_error"), "#ff6b6b");
  }
  function responseError(res) {
    const err = new Error((res && res.error) || "");
    err.code = (res && res.code) || "";
    return err;
  }
  function copyToClipboard(text) {
    if (!text) return Promise.resolve(false);
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      return navigator.clipboard.writeText(text).then(() => true).catch(() => fallbackCopy(text));
    }
    return Promise.resolve(fallbackCopy(text));
  }
  function fallbackCopy(text) {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      ta.style.top = "-9999px";
      ta.setAttribute("readonly", "");
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch (_) {
      return false;
    }
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
    const q = (els.domainsSearch && els.domainsSearch.value || "").trim().toLowerCase();
    applySearchFilter(els.domainsList, ".domain-item", q, els.domainsEmpty, I18n.t("empty_domains"));
    if (q) {
      els.domainsList.querySelectorAll(".domain-node").forEach(node => {
        const h = (node.dataset.host || "").toLowerCase();
        if (h.indexOf(q) >= 0) {
          let p = node.parentElement ? node.parentElement.closest(".domain-node") : null;
          while (p) {
            p.classList.add("expanded");
            p = p.parentElement ? p.parentElement.closest(".domain-node") : null;
          }
        }
      });
    }
  }
  function filterProxies() {
    applySearchFilter(els.pCont, ".list-card", els.proxySearch && els.proxySearch.value, els.proxyEmpty, I18n.t("empty_proxies"));
  }
  function filterLists() {
    applySearchFilter(els.lCont, ".list-card", els.listsSearch && els.listsSearch.value, els.listsEmpty, I18n.t("empty_lists"));
  }

  async function triggerTabReload(tabId) {
    if (tabId == null || tabId < 0) return;
    // Allow background proxy settings (PAC script) to be committed before reloading tab
    await new Promise(r => setTimeout(r, 120));
    try {
      const targetUrl = (activeTab && activeTab._targetUrl) || "";
      if (targetUrl) {
        let targetHost = "";
        try { targetHost = new URL(targetUrl).hostname.toLowerCase(); } catch (_) {}
        const currentTabUrl = (activeTab && activeTab.url) || "";
        let currentHost = "";
        try { currentHost = new URL(currentTabUrl).hostname.toLowerCase(); } catch (_) {}
        // If tab errored out, or user navigated to a different site that failed/pending
        if (isErrorTab(activeTab) || (targetHost && currentHost && targetHost !== currentHost)) {
          await browser.tabs.update(tabId, { url: targetUrl });
          return;
        }
      }
      if (activeTab && isErrorTab(activeTab)) {
        const webUrl = getTabWebUrl(activeTab);
        if (webUrl) {
          await browser.tabs.update(tabId, { url: webUrl });
          return;
        }
      }
      await browser.tabs.reload(tabId, { bypassCache: true });
    } catch (_) {
      try { await browser.tabs.reload(tabId); } catch (_) {}
    }
  }

  async function checkAutoReload(rule) {
    if (!activeTab || activeTab.id == null) return;
    try {
      const tabWebUrl = (activeTab && activeTab._targetUrl) || getTabWebUrl(activeTab);
      let shouldReload = false;
      const targetRuleHost = hostOfRule(rule) || String(rule || "").replace(/^\*\./, "").toLowerCase();

      if (tabWebUrl) {
        const host = new URL(tabWebUrl).hostname.toLowerCase();
        if (matches(host, rule) || (pageHost && matches(pageHost, rule)) || (pageApex && matches(pageApex, rule))) {
          shouldReload = true;
        }
      } else if (isErrorTab(activeTab)) {
        if (!targetRuleHost || targetRuleHost === pageHost || targetRuleHost === pageApex || (activeTab.title && activeTab.title.toLowerCase().includes(targetRuleHost))) {
          shouldReload = true;
        }
      }

      if (shouldReload) {
        await triggerTabReload(activeTab.id);
      }
    } catch (_) {}
  }

  async function saveRules() {
    await browser.storage.local.set({ proxyRules: currentRules, directRules: currentDirect });
  }

  async function fetchTabDomains() {
    const set = new Set();
    const requestedSet = new Set();
    const webUrl = getTabWebUrl(activeTab);
    if (webUrl) {
      try {
        const host = new URL(webUrl).hostname;
        if (host && !HostRules.isIgnoredHost(host)) {
          const h = host.toLowerCase();
          set.add(h);
          requestedSet.add(h);
        }
      } catch (_) {}
    } else if (pageHost && !HostRules.isIgnoredHost(pageHost)) {
      const h = pageHost.toLowerCase();
      set.add(h);
      requestedSet.add(h);
    }
    if (activeTab && activeTab.id != null && activeTab.id >= 0) {
      try {
        const res = await browser.runtime.sendMessage({ action: "getTabDomains", tabId: activeTab.id });
        (res && res.domains ? res.domains : []).forEach(d => {
          const h = String(d || "").trim().toLowerCase();
          if (h && !HostRules.isIgnoredHost(h)) {
            set.add(h);
            requestedSet.add(h);
          }
        });
      } catch (_) {}
    }
    loadedTabHosts = requestedSet;
    return Array.from(set).sort();
  }

  function renderDomainsList(domains, covers) {
    els.domainsList.textContent = "";
    const uniq = [];
    (domains || []).forEach(d => {
      const h = String(d || "").trim().toLowerCase();
      if (h && !HostRules.isIgnoredHost(h) && uniq.indexOf(h) < 0) uniq.push(h);
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
      const host = pick.dataset.host || hostOfRule(pick.dataset.rule);
      paintHostStatus(mark, host, covers, overlay || collectOverlayRules());
    }
    function refreshAllDomainLines() {
      const overlay = collectOverlayRules();
      els.domainsList.querySelectorAll(".domain-line").forEach(line => refreshDomainLine(line, overlay));
    }
    function syncApex(apex, checked, direct, wild) {
      els.domainsList.querySelectorAll("input.domain-pick").forEach(box => {
        if (box.dataset.kind !== "apex" || box.dataset.apex !== apex) return;
        box.checked = checked;
        const line = box.closest(".domain-line");
        const mode = line && line.querySelector("input.mode-direct");
        if (mode && direct != null) mode.checked = direct;
        const wildBtn = line && line.querySelector(".domain-wildcard-btn");
        if (wildBtn && wild != null) wildBtn.classList.toggle("active", wild);
      });
      refreshAllDomainLines();
    }

    function renderDomainNode(parent, host, kind, apex, level, isBold, children) {
      const hasChildren = Array.isArray(children) && children.length > 0;
      const isIp = isIpHost(host);
      const existing = existingUserRule(host);
      const isDirect = existing && isDirectRule(existing);
      const isWild = isIp ? false : (existing ? existing.startsWith("*.") : true);
      const isLoaded = loadedTabHosts.has(host);

      const nodeEl = document.createElement("div");
      nodeEl.className = "domain-node";
      nodeEl.dataset.host = host;
      nodeEl.dataset.level = String(level);

      const expanderHtml = hasChildren
        ? `<span class="domain-expander has-children">${SVGS.chevron}</span>`
        : "";
      const wildBtnTitle = escapeHtml(I18n.t("wildcard_subdomains"));
      const wildBtnHtml = isIp
        ? ""
        : `<button type="button" class="wildcard-btn domain-wildcard-btn ${isWild ? "active" : ""}" title="${wildBtnTitle}">*.</button>`;
      const loadedBadgeHtml = isLoaded
        ? `<span class="loaded-dot" title="${escapeHtml(I18n.t("loaded_domain"))}"></span>`
        : "";

      const line = document.createElement("div");
      line.className = `domain-line${existing ? " picked" : ""}${hasChildren ? " has-children" : ""}${isLoaded ? " loaded" : ""}`;
      line.innerHTML = `
        <input type="checkbox" class="domain-pick" aria-label="${escapeHtml(host)}" data-host="${escapeHtml(host)}" data-kind="${kind}" data-apex="${escapeHtml(apex)}" ${existing ? "checked" : ""}>
        ${expanderHtml}
        ${wildBtnHtml}
        <span class="${isBold ? "domain-name" : "domain-apex"}" title="${escapeHtml(host)}">${escapeHtml(host)}</span>
        ${loadedBadgeHtml}
        <span class="mini-status"></span>
        <span class="domain-spacer"></span>
        <label class="mode-wrap" title="${escapeHtml(I18n.t("mode_proxy_direct"))}">
          <span class="switch mode-switch">
            <input type="checkbox" class="mode-direct" aria-label="${escapeHtml(I18n.t("mode_proxy_direct"))}" ${isDirect ? "checked" : ""}>
            <span class="switch-ui"></span>
          </span>
        </label>
      `;

      const cb = line.querySelector("input.domain-pick");
      const wildBtn = line.querySelector(".domain-wildcard-btn");
      const mode = line.querySelector("input.mode-direct");
      const modeWrap = line.querySelector(".mode-wrap");

      cb.addEventListener("click", e => e.stopPropagation());
      if (wildBtn) {
        wildBtn.addEventListener("click", e => {
          e.stopPropagation();
          wildBtn.classList.toggle("active");
          const isW = wildBtn.classList.contains("active");
          if (kind === "apex") syncApex(apex, cb.checked, mode.checked, isW);
          else refreshAllDomainLines();
        });
      }
      modeWrap.addEventListener("click", e => e.stopPropagation());

      const onToggle = () => {
        const isW = wildBtn ? wildBtn.classList.contains("active") : false;
        if (kind === "apex") syncApex(apex, cb.checked, mode.checked, isW);
        else refreshAllDomainLines();
      };
      cb.addEventListener("change", onToggle);
      mode.addEventListener("change", onToggle);

      if (hasChildren) {
        const toggleExp = e => {
          e.stopPropagation();
          nodeEl.classList.toggle("expanded");
        };
        line.addEventListener("click", toggleExp);
      }

      line.addEventListener("contextmenu", e => {
        e.preventDefault();
        e.stopPropagation();
        const textToCopy = hostOfRule(host) || String(host || "").replace(/^\*\./, "").trim();
        if (!textToCopy) return;
        copyToClipboard(textToCopy).then(ok => {
          if (ok) {
            flash(I18n.t("msg_copied"));
          } else {
            flash(I18n.t("msg_error"), "#ff6b6b");
          }
        });
      });

      refreshDomainLine(line);
      nodeEl.appendChild(line);

      if (hasChildren) {
        const childrenEl = document.createElement("div");
        childrenEl.className = "domain-children";
        children.forEach(child => {
          renderDomainNode(childrenEl, child.host, "host", apex, level + 1, false, child.children);
        });
        nodeEl.appendChild(childrenEl);
      }

      parent.appendChild(nodeEl);
      return nodeEl;
    }

    const pageHostKey = (pageHost || "").toLowerCase();
    const pageApexKey = (pageApex || (pageHostKey ? apexDomain(pageHostKey) || pageHostKey : "")).toLowerCase();

    if (!showDomainTree) {
      // Flat list mode: sort pageHost first, then alphabetically
      const sorted = uniq.slice().sort((a, b) => {
        const aPage = pageHostKey && a === pageHostKey;
        const bPage = pageHostKey && b === pageHostKey;
        if (aPage !== bPage) return aPage ? -1 : 1;
        const aApex = pageApexKey && a === pageApexKey;
        const bApex = pageApexKey && b === pageApexKey;
        if (aApex !== bApex) return aApex ? -1 : 1;
        return a.localeCompare(b);
      });
      sorted.forEach(host => {
        const item = document.createElement("div");
        item.className = "domain-item";
        item.dataset.search = host;
        const apex = apexDomain(host) || host;
        renderDomainNode(item, host, "host", apex, 0, true, []);
        els.domainsList.appendChild(item);
      });
    } else {
      // Tree mode: hierarchical structure grouped by apex
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
          renderDomainNode(item, normalize(apex), "apex", apex, 0, true, []);
        } else {
          const tree = buildDomainTree(hosts, apex);
          function addTreeSearchBits(node) {
            searchBits.push(node.host);
            node.children.forEach(addTreeSearchBits);
          }
          tree.forEach(addTreeSearchBits);
          const apexNode = renderDomainNode(item, apex, "apex", apex, 0, true, tree);
          if (tree.length > 0) {
            apexNode.classList.add("expanded");
          }
        }
        hosts.forEach(h => { if (searchBits.indexOf(h) < 0) searchBits.push(h); });
        item.dataset.search = searchBits.join(" ");
        els.domainsList.appendChild(item);
      });
    }

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
    els.domainsList.querySelectorAll(".domain-line").forEach(line => {
      const cb = line.querySelector("input.domain-pick");
      if (!cb) return;
      const host = cb.dataset.host;
      if (!host) return;
      const wildBtn = line.querySelector(".domain-wildcard-btn");
      const isWild = isIpHost(host) ? false : (wildBtn && wildBtn.classList.contains("active"));
      const rule = isIpHost(host) ? normalize(host) : (isWild ? "*." + host : host);
      const mode = line.querySelector("input.mode-direct");
      const direct = !!(mode && mode.checked);
      const prev = listed.get(host);
      listed.set(host, { rule, host, want: cb.checked || (prev && prev.want), direct: cb.checked ? direct : (prev && prev.direct) });
    });
    listed.forEach(({ rule, host, want, direct }) => {
      const existing = existingUserRule(host);
      const act = direct ? "direct" : "proxy";
      if (want) {
        const wasDirect = existing && isDirectRule(existing);
        if (!existing) { setUserRule(rule, act); added++; }
        else if (wasDirect !== !!direct || normalize(existing) !== normalize(rule)) {
          setUserRule(rule, act);
          changed++;
        }
      } else if (existing) {
        removeUserRulesForHost(host);
        removed++;
      }
    });
    return { added, removed, changed };
  }

  async function reloadActiveTab() {
    if (activeTab && activeTab.id != null) {
      await triggerTabReload(activeTab.id);
    }
  }

  async function refreshDomainsPanel() {
    if (!domainsPanelOpen) return;
    const domains = await fetchTabDomains();
    lastFetchedDomains = domains;
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

  function proxyAddress(p) {
    const host = String((p && p.host) || "").trim();
    const port = Number(p && p.port);
    if (!host) return "";
    return port > 0 ? `${host}:${port}` : host;
  }

  const configFromServers = ProxyConfig.configFromServers;
  const withActiveProxy = ProxyConfig.withActiveProxy;


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
    const on = extensionEnabled && hasConfiguredProxy() && !isConflictBlocked;
    els.powerBtn.classList.toggle("on", on);
    els.powerBtn.classList.toggle("off", !on);
    const label = isConflictBlocked
      ? I18n.t("conflict_warning_title")
      : (!hasConfiguredProxy() ? I18n.t("power_setup") : (on ? I18n.t("power_off") : I18n.t("power_on")));
    els.powerBtn.title = label;
    els.powerBtn.setAttribute("aria-label", label);
    els.powerBtn.setAttribute("aria-pressed", on ? "true" : "false");
  }

  function showProxyTab() {
    activateTab(Array.from(tabs).findIndex(t => t.id === "tabProxy"), false);
  }

  function renderProxies() {
    els.pCont.textContent = "";
    currentProxies.forEach(p => {
      const card = document.createElement("div");
      card.className = `list-card proxy-item${p.enabled ? " active" : ""}`;
      card.title = p.enabled ? I18n.t("proxy_active") : I18n.t("proxy_inactive");
      const name = String(p.name || "").trim();
      const addr = proxyAddress(p);
      card.dataset.search = [name, addr, p.host || ""].filter(Boolean).join(" ");
      const metaBits = [proxyTypeLabel(p.type)];
      const pingData = currentPingResults[p.id];
      let pingHtml = "";
      if (pingData) {
        if (pingData.checking) {
          pingHtml = `<span class="proxy-ping checking" title="${escapeHtml(I18n.t("msg_pinging"))}">...</span>`;
        } else if (pingData.success && Number.isFinite(pingData.latency)) {
          pingHtml = `<span class="proxy-ping good" title="${pingData.latency} ms">${pingData.latency} ms</span>`;
        } else {
          pingHtml = `<span class="proxy-ping bad" title="${escapeHtml(I18n.t("not_available"))}">${escapeHtml(I18n.t("not_available"))}</span>`;
        }
      }

      card.innerHTML = `
        <div class="list-card-body">
          ${name ? `<div class="list-card-title" title="${escapeHtml(name)}">${escapeHtml(name)}</div>` : ""}
          <div class="${name ? "list-card-url" : "list-card-title"}" title="${escapeHtml(addr)}">${escapeHtml(addr)}</div>
          <div class="list-card-meta">${escapeHtml(metaBits.join(" · "))}</div>
        </div>
        <div class="list-card-side">
          ${pingHtml}
          ${p.enabled ? `<span class="proxy-active-badge">${escapeHtml(I18n.t("badge_active"))}</span>` : ""}
          <button type="button" class="btn-edit" title="${escapeHtml(I18n.t("btn_edit"))}" aria-label="${escapeHtml(I18n.t("btn_edit"))}">${SVGS.edit}</button>
        </div>
      `;

      card.addEventListener("click", async () => {
        if (p.enabled) return;
        await persistProxies(currentProxies.map(item => Object.assign({}, item, { enabled: item.id === p.id })));
        flash(I18n.t("msg_active_saved"));
      });

      const editBtn = card.querySelector(".btn-edit");
      if (editBtn) {
        editBtn.addEventListener("click", (e) => {
          e.stopPropagation();
          openProxyForm(p);
        });
      }

      const pingEl = card.querySelector(".proxy-ping");
      if (pingEl) {
        pingEl.addEventListener("click", (e) => e.stopPropagation());
      }

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
  }

  function openProxyForm(item) {
    els.proxyMain.style.display = "none";
    els.proxyForm.style.display = "flex";
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
      const isEnabled = l.enabled !== false;
      const card = document.createElement("div");
      card.className = `list-card${isEnabled ? "" : " list-disabled"}`;
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
      const updateError = ListUpdate.hasUpdateError(l) ? I18n.error(l.updateError, l.updateErrorCode) : "";

      card.innerHTML = `
        <div class="list-card-body">
          ${name ? `<div class="list-card-title" title="${escapeHtml(name)}">${escapeHtml(name)}</div>` : ""}
          <div class="${name ? "list-card-url" : "list-card-title"}" title="${escapeHtml(url)}">${escapeHtml(url)}</div>
          <div class="list-card-meta">${escapeHtml(metaText)}</div>
          <div class="list-card-updated">${escapeHtml(updatedText)}</div>
          ${updateError ? `<div class="list-card-error" title="${escapeHtml(updateError)}">${escapeHtml(updateError)}</div>` : ""}
        </div>
        <div class="list-card-side">
          <label class="switch" title="${isEnabled ? escapeHtml(I18n.t("list_active")) : escapeHtml(I18n.t("list_inactive"))}">
            <input type="checkbox" class="list-toggle" aria-label="${escapeHtml(isEnabled ? I18n.t("list_active") : I18n.t("list_inactive"))}" ${isEnabled ? "checked" : ""}>
            <span class="switch-ui"></span>
          </label>
          <div class="list-card-actions">
            <button type="button" class="btn-refresh" title="${escapeHtml(I18n.t("btn_refresh"))}" aria-label="${escapeHtml(I18n.t("btn_refresh"))}">${SVGS.refresh}</button>
            <button type="button" class="btn-edit" title="${escapeHtml(I18n.t("btn_edit"))}" aria-label="${escapeHtml(I18n.t("btn_edit"))}">${SVGS.edit}</button>
          </div>
        </div>
      `;

      const toggle = card.querySelector(".list-toggle");
      const refreshBtn = card.querySelector(".btn-refresh");

      toggle.addEventListener("change", async () => {
        const nextEnabled = toggle.checked;
        toggle.disabled = true;
        try {
          const result = await sendListMessage({ action: "setListEnabled", id: l.id, enabled: nextEnabled });
          if (!result || !result.success) throw responseError(result);
          l.enabled = nextEnabled;
          card.classList.toggle("list-disabled", !nextEnabled);
          toggle.closest(".switch").title = nextEnabled ? I18n.t("list_active") : I18n.t("list_inactive");
          toggle.setAttribute("aria-label", nextEnabled ? I18n.t("list_active") : I18n.t("list_inactive"));
          flash(nextEnabled ? I18n.t("list_active") : I18n.t("list_inactive"));
        } catch (error) {
          toggle.checked = !nextEnabled;
          flashError(error);
        } finally {
          toggle.disabled = false;
        }
      });

      refreshBtn.addEventListener("click", () => refreshOneList(l.id, refreshBtn));
      card.querySelector(".btn-edit").addEventListener("click", () => openListForm(l));
      els.lCont.appendChild(card);
    });
    filterLists();
  }

  const canonListUrl = ListUpdate.canonListUrl;

  async function showListsMain() {
    editingListId = null;
    els.listsForm.style.display = "none";
    els.listsMain.style.display = "flex";
    try {
      const st = await browser.storage.local.get("proxyLists");
      if (st && Array.isArray(st.proxyLists)) currentLists = st.proxyLists;
    } catch (_) {}
    renderLists();
  }

  function resetListForm() {
    els.lName.value = "";
    els.lUrl.value = "";
    els.lInterval.value = "12";
    els.lViaProxy.checked = false;
  }

  function openListForm(item) {
    els.listsMain.style.display = "none";
    els.listsForm.style.display = "flex";
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
    const existing = editingListId != null ? currentLists.find(l => l.id === editingListId) : null;
    return {
      url,
      name: els.lName.value.trim(),
      intervalHours: hours,
      viaProxy: !!els.lViaProxy.checked,
      enabled: existing ? existing.enabled !== false : true
    };
  }

  async function sendListMessage(payload) {
    let timer = 0;
    try {
      return await Promise.race([
        browser.runtime.sendMessage(payload),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(I18n.t("msg_timeout"))), 60000); })
      ]);
    } finally {
      clearTimeout(timer);
    }
  }

  async function refreshOneList(id, btn) {
    if (btn) { btn.disabled = true; btn.classList.add("busy"); }
    try {
      const res = await sendListMessage({ action: "refreshList", id });
      if (res && res.success) flash(I18n.t("msg_updated"));
      else flashError(res && res.error, res && res.code, "msg_update_error");
    } catch (e) {
      flashError(e, null, "msg_update_error");
    } finally {
      if (btn) { btn.disabled = false; btn.classList.remove("busy"); }
    }
  }

  async function loadState() {
    const res = await browser.storage.local.get(["proxyConfig", "proxyServers", "proxyRules", "directRules", "proxyLists", "extensionEnabled", "proxyApplyError", "proxyApplyErrorCode"]);
    currentRules = Array.isArray(res.proxyRules) ? res.proxyRules : [];
    currentDirect = Array.isArray(res.directRules) ? res.directRules : [];
    currentLists = Array.isArray(res.proxyLists) ? res.proxyLists : [];
    currentProxies = Array.isArray(res.proxyServers) ? res.proxyServers : [];
    extensionEnabled = !!res.extensionEnabled && hasConfiguredProxy();
    renderProxies();
    refreshPowerBtn();
    renderLists();
    try {
      const tab = await queryActiveTab();
      if (tab) {
        activeTab = tab;
        let host = "";
        let currentUrl = "";
        let bgTarget = null;
        if (tab.id != null && tab.id >= 0) {
          try {
            bgTarget = await browser.runtime.sendMessage({ action: "getTabTarget", tabId: tab.id });
          } catch (_) {}
        }

        const tabUrl = String(tab.url || "");
        const pendingUrl = String(tab.pendingUrl || "");
        let tabUrlHost = "";
        try { if (tabUrl.startsWith("http://") || tabUrl.startsWith("https://")) tabUrlHost = new URL(tabUrl).hostname; } catch (_) {}
        let pendingHost = "";
        try { if (pendingUrl.startsWith("http://") || pendingUrl.startsWith("https://")) pendingHost = new URL(pendingUrl).hostname; } catch (_) {}

        const targetHost = (bgTarget && bgTarget.targetHost) || "";
        const targetUrl = (bgTarget && bgTarget.targetUrl) || "";

        // Determine if targetHost represents a new navigation away from previous page:
        // E.g. user was on google.com, then typed rutor.info.
        // If tab.status === "loading", OR isErrorTab(tab), OR targetHost is not sub/parent of tabUrlHost while targetUrl is set:
        const isRedirectOrSameSite = !!(tabUrlHost && targetHost && (
          tabUrlHost === targetHost ||
          tabUrlHost.endsWith("." + targetHost) ||
          targetHost.endsWith("." + tabUrlHost) ||
          apexDomain(tabUrlHost) === apexDomain(targetHost)
        ));

        if (targetHost && (!tabUrlHost || isErrorTab(tab) || tab.status === "loading" || !isRedirectOrSameSite)) {
          // Navigation to a new site (like rutor.info from google.com) or error/loading tab
          host = targetHost;
          currentUrl = targetUrl || pendingUrl || tabUrl;
        } else if (tabUrlHost) {
          // Normal page loaded or successfully redirected (e.g. youtu.be -> youtube.com)
          host = tabUrlHost;
          currentUrl = tabUrl;
        } else if (pendingHost) {
          host = pendingHost;
          currentUrl = pendingUrl;
        } else if (targetHost) {
          host = targetHost;
          currentUrl = targetUrl;
        }

        // Fallback to tab.title if error page and host not found
        if (!host && isErrorTab(tab) && tab.title && !tab.title.includes(" ") && tab.title.includes(".")) {
          try {
            const h = HostRules.canonHost(tab.title);
            if (h && HostRules.isAcceptableHost(h) && !HostRules.isIgnoredHost(h)) host = h;
          } catch (_) {}
        }

        if (currentUrl) {
          activeTab._targetUrl = currentUrl;
        }

        if (host) {
          pageHost = normalize(host).replace(/^\*\./, "");
          pageApex = apexDomain(pageHost);
          scopeMode = "host";
          els.domainInput.value = pageHost;
          if (els.mainWildcard && !isIpHost(pageHost)) {
            const existing = existingUserRule(pageHost);
            if (existing) {
              els.mainWildcard.classList.toggle("active", existing.startsWith("*."));
            } else {
              els.mainWildcard.classList.add("active");
            }
          }
        }
      }
    } catch (_) {}
    refreshScopeUI();
    refreshIcon();
    await checkProxyConflict();
    if (res.proxyApplyError || res.proxyApplyErrorCode) flashError(res.proxyApplyError, res.proxyApplyErrorCode);
  }

  async function checkProxyConflict() {
    try {
      let blocked = false;
      let level = "";

      if (browser.proxy && browser.proxy.settings && typeof browser.proxy.settings.get === "function") {
        try {
          const settings = await new Promise(resolve => {
            browser.proxy.settings.get({ incognito: false }, s => {
              const err = browser.runtime && browser.runtime.lastError;
              resolve(err ? null : s);
            });
          });
          level = (settings && settings.levelOfControl) || "";
          const val = (settings && settings.value) || {};
          const mode = (val && val.mode) || "";

          if (level === "controlled_by_other_extensions" || level === "not_controllable") {
            blocked = true;
          } else if (!extensionEnabled && mode && mode !== "system" && mode !== "direct") {
            blocked = true;
          } else if (extensionEnabled && level === "controllable_by_this_extension" && mode && mode !== "system" && mode !== "direct") {
            blocked = true;
          }
        } catch (_) {}
      }

      if (!blocked) {
        try {
          const res = await browser.runtime.sendMessage({ action: "checkProxyControl" });
          if (res && res.isBlocked) {
            blocked = true;
            level = res.levelOfControl || level;
          }
        } catch (_) {}
      }

      const wasBlocked = isConflictBlocked;
      isConflictBlocked = blocked;
      if (els.conflictBanner) {
        els.conflictBanner.style.display = blocked ? "flex" : "none";
      }
      if (blocked) {
        if (extensionEnabled) {
          extensionEnabled = false;
        }
        refreshPowerBtn();
      } else if (wasBlocked && !blocked) {
        const st = await browser.storage.local.get(["extensionEnabled"]);
        extensionEnabled = !!st.extensionEnabled && hasConfiguredProxy();
        refreshPowerBtn();
        refreshIcon();
      }
    } catch (_) {}
  }

  let isPingingProxies = false;

  async function pingAllProxies() {
    if (isPingingProxies) return;
    if (!currentProxies.length) {
      showToast(I18n.t("msg_no_proxies"), "info");
      return;
    }
    isPingingProxies = true;
    if (els.pingProxies) {
      els.pingProxies.classList.add("busy");
      els.pingProxies.disabled = true;
    }
    showToast(I18n.t("msg_pinging"), "info");

    currentProxies.forEach(p => {
      currentPingResults[p.id] = { checking: true };
    });
    renderProxies();

    try {
      const resp = await browser.runtime.sendMessage({
        action: "pingAllProxies",
        servers: currentProxies
      });
      if (resp && resp.results) {
        Object.keys(resp.results).forEach(id => {
          currentPingResults[id] = resp.results[id];
        });
      }
      showToast(I18n.t("msg_ping_done"), "success");
    } catch (e) {
      showToast(I18n.t("msg_error"), "error");
    } finally {
      isPingingProxies = false;
      if (els.pingProxies) {
        els.pingProxies.classList.remove("busy");
        els.pingProxies.disabled = false;
      }
      renderProxies();
    }
  }

  if (els.pingProxies) {
    els.pingProxies.addEventListener("click", pingAllProxies);
  }

  els.showAddProxy.addEventListener("click", () => openProxyForm(null));
  els.cancelProxy.addEventListener("click", () => showProxyMain());

  els.saveProxy.addEventListener("click", async () => {
    const form = collectProxyForm();
    if (!form.host || !(form.port > 0 && form.port < 65536)) {
      return flash(I18n.t("msg_fill_fields"), "#ff6b6b");
    }
    const dup = currentProxies.find(p => ProxyConfig.proxyKey(p) === ProxyConfig.proxyKey(form) && p.id !== editingProxyId);
    if (dup) return flash(I18n.t("msg_proxy_exists"), "#ff6b6b");
    if (editingProxyId != null) {
      const next = currentProxies.map(p => p.id === editingProxyId ? Object.assign({}, p, form) : p);
      await persistProxies(next);
      flash(I18n.t("msg_proxy_saved"));
    } else {
      const item = Object.assign({ id: ProxyConfig.uniqueId(), enabled: !currentProxies.length }, form);
      await persistProxies(currentProxies.concat(item));
      flash(I18n.t("msg_proxy_added"));
    }
    showProxyMain();
  });

  els.deleteProxy.addEventListener("click", async () => {
    if (editingProxyId == null) return;
    delete currentPingResults[editingProxyId];
    await persistProxies(currentProxies.filter(p => p.id !== editingProxyId));
    flash(I18n.t("msg_proxy_deleted"));
    showProxyMain();
  });

  els.toggleRule.addEventListener("click", async () => {
    const raw = els.domainInput.value;
    const trimmed = raw.trim();
    const rule = effectiveInputRule();
    if (!rule) {
      const msg = !trimmed ? I18n.t("hint_empty_rule") : /\s/.test(trimmed) ? I18n.t("hint_no_spaces") : hasNonLatin(trimmed) ? I18n.t("hint_latin_only") : I18n.t("hint_dot_required");
      return flash(msg, "#ff6b6b");
    }
    const existing = existingUserRule(rule);
    if (existing) {
      removeUserRulesForHost(existing);
      await saveRules();
      refreshIcon();
      flash(I18n.t("msg_deleted"));
    } else {
      setUserRule(rule, "proxy");
      await saveRules();
      refreshIcon();
      flash(I18n.t("msg_rule_added"));
    }
    syncOpenDomainLine(existing || rule);
    checkAutoReload(existing || rule);
  });

  els.domainDirect.addEventListener("change", async () => {
    const rule = effectiveInputRule();
    const existing = existingUserRule(rule);
    if (!rule || !existing) {
      els.domainDirect.checked = false;
      return;
    }
    setUserRule(existing, els.domainDirect.checked ? "direct" : "proxy");
    await saveRules();
    refreshIcon();
    flash(els.domainDirect.checked ? I18n.t("rule_direct") : I18n.t("rule_proxy"));
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
      flash(parts.join(", ") || I18n.t("msg_saved"));
    }
    const target = hostOfRule(els.domainInput.value) || normalize(els.domainInput.value);
    const shown = existingUserRule(target);
    if (shown) {
      els.domainInput.value = hostOfRule(shown) || shown;
      if (els.mainWildcard && !isIpHost(shown)) {
        els.mainWildcard.classList.toggle("active", shown.startsWith("*."));
      }
    }
    refreshIcon();
    closeDomainsPanel();
    if (added || removed || changed) await reloadActiveTab();
  });
  els.cancelDomains.addEventListener("click", () => closeDomainsPanel());
  if (els.toggleDomainTree) {
    els.toggleDomainTree.addEventListener("click", () => {
      showDomainTree = !showDomainTree;
      els.toggleDomainTree.classList.toggle("active", showDomainTree);
      const titleKey = showDomainTree ? "btn_show_flat" : "btn_show_tree";
      const titleText = I18n.t(titleKey);
      els.toggleDomainTree.title = titleText;
      els.toggleDomainTree.setAttribute("aria-label", titleText);
      renderDomainsList(lastFetchedDomains, domainCovers);
    });
  }
  if (els.domainsSearch) els.domainsSearch.addEventListener("input", filterDomainsList);
  if (els.proxySearch) els.proxySearch.addEventListener("input", filterProxies);
  if (els.listsSearch) els.listsSearch.addEventListener("input", filterLists);

  els.showAddList.addEventListener("click", () => openListForm(null));
  els.cancelList.addEventListener("click", () => showListsMain());

  els.saveList.addEventListener("click", async () => {
    const form = collectListForm();
    if (!ListUpdate.validListUrl(form.url)) return flash(I18n.t("msg_invalid_url"), "#ff6b6b");
    const dup = currentLists.find(l => canonListUrl(l.url) === canonListUrl(form.url) && l.id !== editingListId);
    if (dup) return flash(I18n.t("msg_list_exists"), "#ff6b6b");
    els.saveList.disabled = true;
    els.saveList.classList.add("busy");
    els.saveList.textContent = I18n.t("btn_saving");
    try {
      const existing = editingListId != null ? currentLists.find(l => l.id === editingListId) : null;
      const urlChanged = existing && canonListUrl(existing.url) !== canonListUrl(form.url);
      const proxyChanged = existing && !!existing.viaProxy !== form.viaProxy;
      const hasError = !!(existing && ListUpdate.hasUpdateError(existing));
      const needFetch = !existing || urlChanged || proxyChanged || hasError;
      const res = await sendListMessage(needFetch
        ? { action: "fetchList", id: editingListId, url: form.url, name: form.name, intervalHours: form.intervalHours, viaProxy: form.viaProxy, enabled: form.enabled }
        : { action: "saveListMeta", id: editingListId, url: form.url, name: form.name, intervalHours: form.intervalHours, viaProxy: form.viaProxy, enabled: form.enabled });
      if (res && res.success) {
        try {
          const st = await browser.storage.local.get("proxyLists");
          if (st && Array.isArray(st.proxyLists)) currentLists = st.proxyLists;
        } catch (_) {}
        flash(existing ? I18n.t("msg_saved") : I18n.t("msg_list_added"));
        showListsMain();
      } else flashError(res && res.error, res && res.code);
    } catch (e) {
      flashError(e);
    } finally {
      els.saveList.disabled = false;
      els.saveList.classList.remove("busy");
      els.saveList.textContent = I18n.t("btn_save");
    }
  });

  els.deleteList.addEventListener("click", async () => {
    if (editingListId == null) return;
    try {
      const result = await sendListMessage({ action: "deleteList", id: editingListId });
      if (!result || !result.success) throw responseError(result);
      currentLists = currentLists.filter(x => x.id !== editingListId);
      flash(I18n.t("msg_deleted"));
      showListsMain();
    } catch (error) {
      flashError(error);
    }
  });

  els.refreshLists.addEventListener("click", async () => {
    if (!currentLists.length) return flash(I18n.t("msg_no_lists"), "#ff6b6b");
    els.refreshLists.disabled = true;
    els.refreshLists.classList.add("busy");
    try {
      const res = await sendListMessage({ action: "refreshLists" });
      if (res && res.success) {
        const failed = Number(res.failed) || 0;
        if (failed) flash(I18n.t("msg_updated_failed", { updated: res.updated || 0, failed }), "#ff6b6b");
        else flash(I18n.t("msg_updated_count", { count: res.updated || 0 }));
      }
      else flashError(res && res.error, res && res.code, "msg_update_error");
    } catch (e) {
      flashError(e, null, "msg_update_error");
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
  document.querySelectorAll(".info-link").forEach(a => {
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
    let val = els.domainInput.value;
    const blockedLatin = hasNonLatin(val);
    if (blockedLatin) val = stripNonLatin(val);
    if (val.startsWith("*.")) {
      if (els.mainWildcard) els.mainWildcard.classList.add("active");
      val = val.slice(2);
    }
    els.domainInput.value = val;
    const h = hostOfRule(val);
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

  if (els.mainWildcard) {
    els.mainWildcard.addEventListener("click", () => {
      els.mainWildcard.classList.toggle("active");
      refreshIcon();
    });
  }

  els.powerBtn.addEventListener("click", async () => {
    if (isConflictBlocked) {
      showToast(I18n.t("conflict_warning_desc"), "error");
      return;
    }
    if (!hasConfiguredProxy()) {
      showProxyTab();
      flash(I18n.t("msg_setup_proxy_first"), "#ff6b6b");
      return;
    }
    extensionEnabled = !extensionEnabled;
    await browser.storage.local.set({ extensionEnabled, disabledByConflict: false });
    refreshPowerBtn();
    await checkProxyConflict();
  });

  function openInfoModal() {
    if (els.infoModal) els.infoModal.classList.add("open");
  }
  function closeInfoModal() {
    if (els.infoModal) els.infoModal.classList.remove("open");
  }
  if (els.infoBtn) els.infoBtn.addEventListener("click", openInfoModal);
  if (els.closeInfoBtn) els.closeInfoBtn.addEventListener("click", closeInfoModal);
  if (els.infoModal) {
    els.infoModal.addEventListener("click", (e) => {
      if (e.target === els.infoModal) closeInfoModal();
    });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (els.infoModal && els.infoModal.classList.contains("open")) {
        closeInfoModal();
      } else if (domainsPanelOpen) {
        closeDomainsPanel();
      }
    }
  });
  try {
    const manifest = browser.runtime.getManifest();
    if (manifest && manifest.version && els.infoVersion) {
      els.infoVersion.textContent = "v" + manifest.version;
    }
  } catch (_) {}

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
      extensionEnabled = !!c.extensionEnabled.newValue && hasConfiguredProxy() && !isConflictBlocked;
      refreshPowerBtn();
    }
  });

  await loadState();
});
