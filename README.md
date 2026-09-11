# DeviateProxy

Расширение для выборочного проксирования сайтов по правилам через SOCKS5, HTTP и HTTPS.

Поддерживает **Firefox** (ПК и Android) и браузеры на базе **Chromium** (Google Chrome, Microsoft Edge, Opera, Brave, Vivaldi, Яндекс Браузер).

## Функции

- **Выборочное проксирование**: списки правил для проксирования и прямого подключения (Direct).
- **Поддержка масок и поддоменов**: обработка поддоменов и масок вида `*.example.com`.
- **IP-адреса и подсети**: поддержка отдельных IPv4-адресов и диапазонов CIDR.
- **Удаленные списки**: загрузка списков по URL с автоматическим обновлением по расписанию (поддерживаются текстовые форматы, adblock-синтаксис и PAC-скрипты).
- **Инспектор доменов вкладки**: список внешних хостов, запрошенных активной вкладкой, с добавлением в правила в один клик.
- **Индикатор на иконке**: счетчик проксированных запросов для текущей вкладки.
- **Профили серверов**: сохранение нескольких конфигураций прокси (SOCKS5, HTTP, HTTPS) с поддержкой авторизации.
- **Переключатель работы**: включение и отключение расширения одной кнопкой.

## Структура проекта

```text
deviateproxy/
├── src/
│   ├── common/             # Общие ресурсы и логика (UI, иконки, парсеры списков)
│   ├── firefox/            # Манифест и скрипты для Firefox (Gecko)
│   └── chrome/             # Манифест и скрипты для Chromium (Chrome, Edge, Opera)
├── scripts/
│   ├── package.py          # Сборка пакетов (Python)
│   └── package.ps1         # Сборка пакетов (PowerShell)
└── .github/workflows/
    └── build-extension.yml # Автоматическая сборка в GitHub Actions
```

## Сборка

```bash
python3 scripts/package.py
# или в PowerShell (Windows):
powershell -ExecutionPolicy Bypass -File scripts/package.ps1
```

Результаты сборки сохраняются в папку `dist/`.

---

Репозиторий: [github.com/devintly/deviateproxy](https://github.com/devintly/deviateproxy)  
Базовая основа: [github.com/ventordimi/meguproxy](https://github.com/ventordimi/meguproxy)
