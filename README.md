# DeviateProxy

Эффективное, быстрое и минималистичное расширение для выборочного проксирования сайтов по правилам (SOCKS5 / HTTP / HTTPS).

Поддерживает **Firefox** (ПК и Android), **Google Chrome** и **Microsoft Edge**.

## Возможности

- **Выборочное проксирование**: раздельные списки доменов и IP для проксирования и прямого подключения (Direct).
- **Поддержка масок и поддоменов**: автоматический учет поддоменов и масок вида `*.example.com`.
- **Быстрые удаленные списки**: поддержка списков доменов и сжатых PAC-скриптов (включая АнтиЗапрет LZP).
- **Мгновенный отклик**: $O(1)$ хэш-таблицы правил без линейных переборов $O(N)$ даже при сотнях тысяч доменов.
- **Инспектор доменов вкладки**: просмотр всех внешних хостов, запрошенных активной вкладкой, и быстрое добавление в правила в один клик.
- **Счетчик на иконке**: отображение количества проксированных запросов для текущей вкладки.
- **Менеджер серверов**: сохранение нескольких профилей прокси с быстрым переключением.
- **Главный выключатель**: мгновенное включение и отключение расширения.

## Структура проекта

```text
deviateproxy/
├── src/
│   ├── common/             # Общие ресурсы и логика (UI, иконки, парсеры списков)
│   │   ├── icons/          # Иконки расширения
│   │   ├── popup.html/js   # Главный интерфейс
│   │   ├── list.html/js    # Редактор правил
│   │   ├── pac-parse.js    # Разбор PAC и списков
│   │   ├── list-update.js  # Управление периодическими обновлениями
│   │   └── list-ingest.js  # Обработка загруженного контента
│   ├── firefox/            # Специфичные файлы Firefox (Gecko MV3, browser.proxy.onRequest)
│   ├── chrome/             # Специфичные файлы Chrome (Chromium MV3 Service Worker, PAC generator)
│   └── edge/               # Специфичные файлы Edge (Edge Addons MV3 Service Worker)
├── scripts/
│   ├── package.py          # Кроссплатформенный скрипт сборки пакетов
│   └── package.ps1         # Скрипт сборки для Windows (PowerShell)
└── .github/workflows/
    └── build-extension.yml # Автоматическая сборка в GitHub Actions
```

Каждая сборка содержит **только код своего целевого браузера** без избыточных файлов.

## Сборка

Для сборки всех пакетов выполните:

```bash
python3 scripts/package.py
```

Или в PowerShell на Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/package.ps1
```

Готовые файлы появятся в директории `dist/`:
- `deviateproxy-firefox-*.xpi` / `.zip` (для Firefox)
- `deviateproxy-chrome-*.zip` (для Chrome Web Store)
- `deviateproxy-edge-*.zip` (для Microsoft Edge Addons)
- `dist/unpacked/{firefox,chrome,edge}/` — распакованные версии для быстрой загрузки в режиме разработчика (`about:debugging` или `chrome://extensions`).

---

Репозиторий: [github.com/devintly/deviateproxy](https://github.com/devintly/deviateproxy)  
Базовая основа: [github.com/ventordimi/meguproxy](https://github.com/ventordimi/meguproxy)
