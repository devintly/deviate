"use strict";

(function (root) {
  const MESSAGES = {
    ru: {
      tabs_proxy: "Прокси",
      tabs_rules: "Правила",
      tabs_lists: "Списки",
      power_setup: "Сначала добавьте прокси",
      power_off: "Выключить расширение",
      power_on: "Включить расширение",
      search_domains: "Поиск домена",
      search_proxies: "Поиск по названию, IP или домену",
      search_lists: "Поиск по названию или ссылке",
      empty_domains: "Нет доменов. Откройте сайт и обновите страницу.",
      empty_proxies: "Прокси пока нет",
      empty_lists: "Списков пока нет",
      empty_generic: "Ничего не найдено",
      proxy_active: "Активный прокси",
      proxy_inactive: "Сделать активным",
      btn_edit: "Редактировать",
      btn_refresh: "Обновить",
      btn_delete: "Удалить",
      btn_save: "Сохранить",
      btn_saving: "Сохранение...",
      btn_cancel: "Отмена",
      btn_add_proxy: "Добавить прокси",
      btn_add_list: "Добавить список",
      btn_update_all: "Обновить все",
      btn_ping_all: "Проверить пинг",
      lbl_protocol: "Тип прокси",
      lbl_host: "IP адрес / Хост",
      lbl_port: "Порт",
      lbl_username: "Логин",
      lbl_password: "Пароль",
      lbl_name: "Название",
      lbl_url: "URL списка (TXT / PAC)",
      lbl_interval: "Обновление (часы)",
      lbl_via_proxy: "Скачивать через прокси",
      lbl_scope_host: "Текущий",
      lbl_scope_apex: "Основной",
      btn_tab_domains: "Домены вкладки",
      btn_rule_editor: "Редактор правил",
      rule_proxy: "Проксировать",
      rule_direct: "Напрямую",
      btn_to_rules: "Создать правило",
      btn_remove_rule: "Удалить",
      domain_placeholder: "example.com или *.example.com",
      status_none: "Нет правил",
      status_proxy_full: "Проксируется",
      status_direct_full: "Идёт напрямую",
      status_proxy_apex: "Проксируется правилом",
      status_direct_apex: "Идёт напрямую правилом",
      status_list_full: "Проксируется списком",
      status_list_apex: "Проксируется списком по правилу",
      hint_no_spaces: "Уберите пробелы",
      hint_latin_only: "Только латиница",
      hint_dot_required: "Нужна точка в домене",
      hint_empty_rule: "Пустое правило",
      msg_proxy_saved: "Сохранено",
      msg_proxy_added: "Прокси добавлен",
      msg_proxy_deleted: "Прокси удален",
      msg_fill_fields: "Заполните хост и порт",
      msg_proxy_exists: "Прокси добавить нельзя, он уже существует",
      msg_invalid_url: "Введите корректный URL",
      msg_list_exists: "Список добавить нельзя, он уже существует",
      msg_list_added: "Список добавлен",
      msg_no_lists: "Списков нет",
      msg_no_proxies: "Нет прокси для проверки",
      msg_pinging: "Проверка прокси...",
      msg_ping_done: "Проверка завершена",
      msg_active_saved: "Активный прокси выбран",
      msg_saved: "Сохранено",
      msg_deleted: "Удалено",
      msg_added: "добавлено: {count}",
      msg_removed: "удалено: {count}",
      msg_setup_proxy_first: "Сначала добавьте прокси",
      updated_ago_min: "{n} мин. назад",
      updated_ago_hr: "{n} ч. назад",
      updated_ago_day: "{n} дн. назад",
      updated_just_now: "только что",
      updated_never: "еще не обновлялся",
      lbl_updated: "Обновлён",
      list_editor_title: "Редактор правил",
      list_editor_proxy: "Проксировать",
      list_editor_direct: "Напрямую",
      list_editor_save: "Сохранить",
      list_editor_saved: "Сохранено",
      status_proxied_by_rule: "Проксируется правилом {rule}",
      status_direct_by_rule: "Идёт напрямую правилом {rule}",
      status_proxied_by_list: "Проксируется списком {name}",
      status_proxied_by_list_rule: "Проксируется списком {name} по правилу {rule}",
      mode_proxy_direct: "Проксировать / Напрямую",
      msg_timeout: "Таймаут",
      msg_updated: "Обновлено",
      msg_update_error: "Ошибка обновления",
      msg_error: "Ошибка",
      msg_updated_count: "Обновлено: {count}",
      msg_updated_failed: "Обновлено: {updated}, ошибок: {failed}",
      msg_rule_added: "Добавлено",
      placeholder_proxy_name: "Если пусто — будет адрес",
      placeholder_list_name: "Если пусто — будет ссылка",
      placeholder_list_url: "https://.../filter.txt или https://.../proxy.pac",
      conflict_warning_title: "Конфликт расширений",
      conflict_warning_desc: "Другое расширение контролирует настройки прокси. Отключите конфликтующие VPN или прокси-расширения.",
      info_title: "О расширении",
      info_version: "Версия {version}",
      info_desc: "Проксирование сайтов через SOCKS/HTTP/HTTPS по пользовательским правилам с поддержкой импорта TXT/PAC списков.",
      info_source_link: "Исходный код (GitHub)",
      info_inspired_link: "Вдохновлено MeguProxy"
    },
    en: {
      tabs_proxy: "Proxy",
      tabs_rules: "Rules",
      tabs_lists: "Lists",
      power_setup: "Configure proxy first",
      power_off: "Disable extension",
      power_on: "Enable extension",
      search_domains: "Search domain",
      search_proxies: "Search by name, IP, or domain",
      search_lists: "Search by name or URL",
      empty_domains: "No domains. Open a website and reload the page.",
      empty_proxies: "No proxies yet",
      empty_lists: "No lists yet",
      empty_generic: "Nothing found",
      proxy_active: "Active proxy",
      proxy_inactive: "Set as active",
      btn_edit: "Edit",
      btn_refresh: "Update",
      btn_delete: "Delete",
      btn_save: "Save",
      btn_saving: "Saving...",
      btn_cancel: "Cancel",
      btn_add_proxy: "Add Proxy",
      btn_add_list: "Add List",
      btn_update_all: "Update All",
      btn_ping_all: "Check ping",
      lbl_protocol: "Proxy type",
      lbl_host: "IP / Host",
      lbl_port: "Port",
      lbl_username: "Username",
      lbl_password: "Password",
      lbl_name: "Name",
      lbl_url: "List URL (TXT / PAC)",
      lbl_interval: "Update interval (hours)",
      lbl_via_proxy: "Download via proxy",
      lbl_scope_host: "Current",
      lbl_scope_apex: "Apex",
      btn_tab_domains: "Tab domains",
      btn_rule_editor: "Rule editor",
      rule_proxy: "Proxy",
      rule_direct: "Direct",
      btn_to_rules: "Add rule",
      btn_remove_rule: "Remove",
      domain_placeholder: "example.com or *.example.com",
      status_none: "No rules",
      status_proxy_full: "Proxied",
      status_direct_full: "Direct",
      status_proxy_apex: "Proxied by rule",
      status_direct_apex: "Direct by rule",
      status_list_full: "Proxied by list",
      status_list_apex: "Proxied by list rule",
      hint_no_spaces: "Remove spaces",
      hint_latin_only: "Latin characters only",
      hint_dot_required: "Domain name and dot required",
      hint_empty_rule: "Empty rule",
      msg_proxy_saved: "Saved",
      msg_proxy_added: "Proxy added",
      msg_proxy_deleted: "Proxy deleted",
      msg_fill_fields: "Enter host and port",
      msg_proxy_exists: "Proxy already exists",
      msg_invalid_url: "Enter a valid URL",
      msg_list_exists: "List already exists",
      msg_list_added: "List added",
      msg_no_lists: "No lists",
      msg_no_proxies: "No proxies to check",
      msg_pinging: "Checking proxies...",
      msg_ping_done: "Check complete",
      msg_active_saved: "Active proxy selected",
      msg_saved: "Saved",
      msg_deleted: "Deleted",
      msg_added: "added: {count}",
      msg_removed: "removed: {count}",
      msg_setup_proxy_first: "Configure proxy first",
      updated_ago_min: "{n} min ago",
      updated_ago_hr: "{n} hr ago",
      updated_ago_day: "{n} d ago",
      updated_just_now: "just now",
      updated_never: "never updated",
      lbl_updated: "Updated",
      list_editor_title: "Rule Editor",
      list_editor_proxy: "Proxy",
      list_editor_direct: "Direct",
      list_editor_save: "Save",
      list_editor_saved: "Saved",
      status_proxied_by_rule: "Proxied by rule {rule}",
      status_direct_by_rule: "Direct by rule {rule}",
      status_proxied_by_list: "Proxied by list {name}",
      status_proxied_by_list_rule: "Proxied by list {name} by rule {rule}",
      mode_proxy_direct: "Proxy / Direct",
      msg_timeout: "Timeout",
      msg_updated: "Updated",
      msg_update_error: "Update failed",
      msg_error: "Error",
      msg_updated_count: "Updated: {count}",
      msg_updated_failed: "Updated: {updated}, failed: {failed}",
      msg_rule_added: "Added",
      placeholder_proxy_name: "If empty — host will be used",
      placeholder_list_name: "If empty — URL will be used",
      placeholder_list_url: "https://.../filter.txt or https://.../proxy.pac",
      conflict_warning_title: "Extension Conflict",
      conflict_warning_desc: "Another extension is controlling proxy settings. Please disable conflicting VPN or proxy extensions.",
      info_title: "About DeviateProxy",
      info_version: "Version {version}",
      info_desc: "Website proxying via SOCKS/HTTP/HTTPS using custom rules with support for importing TXT/PAC lists.",
      info_source_link: "Source Code (GitHub)",
      info_inspired_link: "Inspired by MeguProxy"
    }
  };

  let currentLang = "ru";

  function detectLang(browserApi) {
    let lang = "";
    try {
      if (browserApi && browserApi.i18n && typeof browserApi.i18n.getUILanguage === "function") {
        lang = browserApi.i18n.getUILanguage();
      }
    } catch (_) {}
    if (!lang && typeof chrome !== "undefined" && chrome.i18n && typeof chrome.i18n.getUILanguage === "function") {
      try { lang = chrome.i18n.getUILanguage(); } catch (_) {}
    }
    if (!lang && typeof navigator !== "undefined") {
      lang = navigator.language || navigator.userLanguage || "";
    }
    const s = String(lang || "").toLowerCase();
    if (s.startsWith("ru") || s.startsWith("be") || s.startsWith("kk") || s.startsWith("uk")) {
      return "ru";
    }
    return "en";
  }

  function t(key, params) {
    const dict = MESSAGES[currentLang] || MESSAGES.en;
    let str = dict[key] || (MESSAGES.en && MESSAGES.en[key]) || key;
    if (params) {
      Object.keys(params).forEach(p => {
        str = str.replace(new RegExp(`\\{${p}\\}`, "g"), params[p]);
      });
    }
    return str;
  }

  function applyDom() {
    document.querySelectorAll("[data-i18n]").forEach(el => {
      const key = el.getAttribute("data-i18n");
      if (key) el.textContent = t(key);
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
      const key = el.getAttribute("data-i18n-placeholder");
      if (key) el.placeholder = t(key);
    });
    document.querySelectorAll("[data-i18n-title]").forEach(el => {
      const key = el.getAttribute("data-i18n-title");
      if (key) el.title = t(key);
    });
  }

  async function init(browserApi) {
    currentLang = detectLang(browserApi);
    applyDom();
    return currentLang;
  }

  function getLang() {
    return currentLang;
  }

  const I18n = {
    t,
    init,
    getLang,
    applyDom,
    detectLang,
    MESSAGES
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = I18n;
  }
  root.I18n = I18n;
})(typeof self !== "undefined" ? self : this);
