# KeyForge

Локальное десктопное приложение для SSH-ключей и конфигурации. Electron, React, TypeScript и Tailwind CSS. Интерфейс на русском и английском; язык переключается в боковой панели и сохраняется локально.

Темы переключаются в боковой панели и сохраняются локально: Obsidian Monolith (по умолчанию), Tokyo Night Terminal, Paper & Ink, Solarized Machining. Компактная таблица и инспектор используют CSS-переменные, системный UI-шрифт и моноширинный шрифт для технических значений. SHA256 отображается парами символов исходного base64 без изменения отпечатка. Ctrl/Command+K открывает обзор и переводит фокус на выбранный ключ; Ctrl/Command+C копирует его публичный ключ, если фокус не в поле ввода и текст не выделен. Отметка копирования появляется на кнопке на 1,8 секунды.

Индикатор парольной фразы состоит из четырёх сегментов и оценивает длину, а не гарантирует криптографическую стойкость. Индикация FIDO2 использует необязательную утилиту `fido2-token -L` из libfido2: серый — устройство отсутствует или обнаружение недоступно (разные подписи), зелёный — найден физический токен. Windows Hello не считается USB-токеном. Мигающий янтарный означает запрос касания в выводе OpenSSH; при настройке ОС «уменьшить движение» он не мигает. Обновление обнаружения выполняется вручную и раз в пять секунд в аппаратной вкладке/мастере, когда утилита доступна и операция не выполняется. Обнаружение токена не заменяет проверку регистрации и подписи с реальным устройством.

## Возможности

- Парольная фраза шифрует локальный файл: приватный ключ для программных алгоритмов или файл-ссылку для YubiKey. Приватный ключ YubiKey остаётся на токене, а FIDO2 PIN задаётся отдельно. Кнопка «Показать / Скрыть» раскрывает ввод только по запросу; поле снова маскируется при потере фокуса окна и смене раздела. Сохраните сгенерированную фразу в менеджере паролей до создания: при отправке формы поле очищается, в настройках фраза не хранится.
- Обзор `.pub` в стандартном каталоге SSH: алгоритм, размер, комментарий, SHA256 fingerprint, дата изменения, наличие приватного файла и его шифрования.
- Копирование только публичного ключа. Содержимое приватных ключей не передаётся в интерфейс, буфер обмена или журналы.
- Генерация через OpenSSH: Ed25519, ECDSA 256/384/521, RSA 3072/4096, ed25519-sk и ecdsa-sk. RSA 2048 не создаётся.
- Парольная фраза с ориентировочной оценкой длины и криптографическим генератором. Передача через псевдотерминал, без секретов в аргументах процесса. Пустая фраза требует явного согласия в интерфейсе.
- Выбор другого пути через системный диалог. Нельзя перезаписать существующую пару; ключи из других каталогов не входят в стандартный обзор.
- Для FIDO2: `resident`, `verify-required`, запрос PIN, ожидание касания, отмена и тайм-аут. Поддержка алгоритмов OpenSSH проверяется отдельно от обнаружения физического устройства через libfido2.
- Удаление выбранного локального ключа в системную корзину с подтверждением точных путей. Удаляется пара файлов или только `.pub`, если приватного файла нет. Для FIDO2 это удаление локального файла-ссылки; запись на токене, доступ на серверах и копии в Termius сохраняются. Изменившиеся файлы и ссылки отклоняются; при недоступной корзине безвозвратное удаление не выполняется.
- Команды установки публичного ключа для PowerShell/POSIX; интерактивный `ssh-copy-id` на Linux/macOS, если он установлен.
- Кнопка «Команда для сервера» в карточке ключа: подготовка и копирование команды для вставки прямо в терминал сервера. Пустое имя пользователя означает текущую учётную запись; другое имя использует `sudo -u … -H` и требует установленного sudo и соответствующих прав. Команда содержит только ASCII; публичный ключ с Unicode-комментарием восстанавливается из base64 на сервере. Нужны awk, tail и base64. Ключ не дублируется, существующие ограничения в authorized_keys сохраняются.
- Редактор SSH config с визуальным добавлением Host, сохранением исходного текста, резервной копией, проверкой конфликтов и `ssh -G`.
- Справочник SSH + TOTP для Ubuntu/Debian. Это инструкции для администратора, а не автоматическое изменение PAM.

## Скачать готовую сборку

[Скачать KeyForge для Windows x64](https://github.com/angelbana/KeyForge/releases/latest). В разделе Assets выберите файл `KeyForge-0.1.10-windows-x64.zip`, распакуйте весь архив в отдельную папку и запустите `KeyForge/KeyForge.exe`. Node.js, npm и Git для запуска не нужны; клиент OpenSSH должен быть установлен. Сборка пока без цифровой подписи. Готовые пакеты Linux/macOS пока не опубликованы.

## Запуск и сборка

Требуются Git, Node.js 24, npm и клиент OpenSSH (`ssh`, `ssh-keygen`) в PATH. На Windows рекомендуется встроенный OpenSSH. В Linux для сборки node-pty могут понадобиться Python 3, make и C++ compiler; для запуска Electron нужны стандартные библиотеки Chromium. Сборку установщика выполняйте на целевой ОС.

```powershell
git clone https://github.com/angelbana/KeyForge.git
cd KeyForge
npm ci
npm run dev
```

```sh
npm run check         # ESLint, tests, TypeScript, production frontend
npm run smoke         # Real Electron/OpenSSH in an isolated temporary directory
npm run pack          # Unpacked desktop application
npm run dist          # Windows NSIS / Linux AppImage+deb / macOS DMG
```

Команды выполняются из корня клонированного репозитория (`KeyForge/` в примере выше). После `npm run pack` актуальное распакованное приложение находится в соседней папке `../build/` (Windows: `../build/KeyForge.exe`). Промежуточная компиляция и пакеты находятся в `../verification/build-work/`, вне репозитория. Эти каталоги создаются автоматически. Архивы ZIP автоматически не создаются. Для неподписанной Windows-сборки с Electron, установленным через `npm ci`, выполните в PowerShell:

```powershell
npm run build
npm exec electron-builder -- --dir `
  --config.electronDist=node_modules/electron/dist `
  --config.win.signAndEditExecutable=false
node scripts/publish-local-build.cjs
```

Эта команда создаёт неподписанное Windows-приложение и пропускает изменение ресурсов EXE. Обычная `npm run dist` использует стандартный процесс упаковки. Для публичных релизов настройте подписи через защищённые настройки CI.

## Безопасность и ограничения

Windows-сборка включает генератор ключей и FIDO-helper из официального [Microsoft OpenSSH 10.0.0.0p2 Preview](https://github.com/PowerShell/Win32-OpenSSH/releases/tag/10.0.0.0p2-Preview). При сборке архив загружается в `../verification/tools/`, проверяется по закреплённому SHA256 и цифровым подписям Microsoft; лицензии включаются в приложение. Нужен интернет при первой Windows-сборке. Системный OpenSSH не заменяется: он используется для SSH-соединений, а включённые утилиты — для генерации ключей. PIN и подтверждение касания запрашиваются системным окном «Безопасность Windows».

Windows OpenSSH 9.5 может всегда запрашивать перезапись резидентного ключа из-за ошибки проверки существующей записи, даже для новой метки. Ответ «нет» затем отображается как `bad permissions`: это не доказывает отсутствие прав администратора. KeyForge всегда отказывается от перезаписи токена и использует отдельную метку `application=ssh:keyforge:<имя файла>`. Обновлённый генератор устраняет ложный запрос. В форме также показан фактический статус прав; некоторым провайдерам прямого USB-доступа нужны повышенные права. Имеющуюся запись можно восстановить через OpenSSH вместо замены.

Все ключи обрабатываются локально. Основной процесс запускает OpenSSH без shell-интерполяции. Renderer изолирован, работает без Node.js, с sandbox и CSP, без сетевых запросов; IPC проверяет окно и frame отправителя. Приложение не предоставляет просмотр или экспорт приватных ключей.

Символические ссылки, жёсткие ссылки, специальные файлы и файлы более 1 МБ отклоняются. Создание использует отдельный staging-каталог и эксклюзивное копирование. Unix: каталог `700`, файлы пары и конфиг `600`. Windows: ACL каталога и выбранных файлов ограничивается текущим пользователем. Обзор пока показывает статус Windows ACL как «Неизвестно»; исправление прав работает отдельно. Ограничение прав каталога также применяется при выборе пользовательского пути: используйте отдельный каталог SSH.

SSH config сохраняется целиком с нормализацией CRLF → LF. Визуальное добавление ставит новый Host перед существующим текстом, чтобы wildcard-настройки не перекрывали его. Поля существующих Host редактируются в текстовом редакторе. Для безопасного `ssh -G` запрещены `Include`, `Match`, `ProxyCommand`, `LocalCommand` и `KnownHostsCommand`: такие конфиги можно читать, но проверять/сохранять их нужно доверенным внешним редактором. Проверка `ssh -G` не подтверждает сетевой handshake.

Парольные фразы и PIN не сохраняются, а вывод интерактивного OpenSSH не возвращается в UI. JavaScript не гарантирует обнуление строк в оперативной памяти; это не защита от компрометации ОС или чтения памяти процесса. Тайм-аут интерактивных операций — три минуты. При отмене staging удаляется; резидентный credential уже мог появиться на токене и требует ручного удаления. Ошибка прав после создания может оставить готовую пару: проверьте её в обзоре перед повтором.

Команды установки нормализуют CRLF, добавляют недостающий разделитель строк и пропускают уже установленный ключ, сохраняя его ограничения и комментарий. Windows PowerShell 5.1 и PowerShell 7 учитываются отдельно при передаче кавычек нативному SSH. Одновременный запуск нескольких команд установки не синхронизируется. FIDO2, серверное развёртывание и PAM требуют проверки с реальным устройством/сервером. Их успешная работа не выводится из результатов локальных тестов. Linux/macOS сборки должны пройти CI на соответствующих ОС. Ключи без `.pub`, сертификаты OpenSSH, агент SSH и управление resident credentials не входят в эту версию.

GitHub CI запускает проверки и упаковку на трёх ОС, не публикует релизы. Результаты доступны во вкладке Actions репозитория. Аудит инструментов сборки может показывать отдельные проблемы транзитивных devDependencies: смотрите `npm audit`. `npm audit --omit=dev` проверяет runtime-зависимости отдельно.

## English

The passphrase encrypts a local file: a software private key or a hardware key handle. A YubiKey keeps its private key on the token; its FIDO2 PIN is separate. Show/Hide reveals the entered phrase on request, and masks it again on window blur or navigation. Save generated phrases in your password manager before submission: the field is cleared when submitted, and the phrase is not saved in settings.

[Download the Windows x64 build](https://github.com/angelbana/KeyForge/releases/latest). Choose KeyForge-0.1.10-windows-x64.zip under Assets, extract the entire archive and run KeyForge/KeyForge.exe. No Node.js, npm or Git is needed to run the app; OpenSSH is required. The build is unsigned. Linux/macOS packages are not published yet.

KeyForge is a local SSH key manager with Russian and English UI. It uses Electron, React, strict TypeScript and Tailwind CSS. Native OpenSSH creates encrypted software keys and FIDO2 credentials; private material never enters the renderer or clipboard.

Four persisted themes are available: Obsidian Monolith (default), Tokyo Night Terminal, Paper & Ink, and Solarized Machining. Technical data uses monospace typography, SHA256 fingerprints retain their original base64 while being grouped in pairs, and copy actions confirm inline. Ctrl/Command+K focuses the selected key; Ctrl/Command+C copies its public key when no editable field or text selection owns the shortcut. The four-segment passphrase meter estimates length only. Optional libfido2 enumeration distinguishes physical tokens from Windows Hello; unavailable detection is shown explicitly. Amber touch indication follows OpenSSH output and respects reduced motion. Physical enrollment and signing still require separate verification.

Install Git, Node.js 24 and OpenSSH, then clone the repository:

```sh
git clone https://github.com/angelbana/KeyForge.git
cd KeyForge
npm ci
npm run dev
```

Run all npm commands from the cloned repository root. `npm run check` runs lint, parser/service tests, type checks and the frontend build. `npm run smoke` exercises real Electron and OpenSSH in a temporary SSH directory. `npm run pack` places the current unpacked app directly in `../build/` (Windows: `../build/KeyForge.exe`); `npm run dist` creates platform packages in `../verification/build-work/packages/`. Output directories are created automatically outside the repository. Build on each target operating system. Linux may need native build tools for node-pty. The unsigned Windows example above uses PowerShell line continuation and runs `npm run build` before packaging. No cloud service, telemetry or account is required.

The explorer scans the default SSH directory, displays public metadata and copies only public keys. Generation supports Ed25519, NIST ECDSA, RSA 3072/4096 and security key algorithms, with passphrase/PIN prompts through a PTY. Custom save paths require the native file dialog. Existing files cannot be replaced. Unix permissions and Windows ACLs are restricted to the current user; custom destination directories are restricted too. Windows ACL auditing is displayed as unknown.

Deployment provides PowerShell/POSIX commands and optional ssh-copy-id on Unix. The config editor preserves comments and directives, creates backups, checks revisions and uses a validated temporary snapshot for `ssh -G`. Safe validation blocks Include, Match and executable directives. Edit advanced configs in a trusted external editor. Existing Host entries are editable as text; the visual form prepends new Host blocks. No network handshake is implied by local resolution.

The key detail panel also offers a “Command for the server” button. Paste the copied command into a Linux/macOS server terminal. Leave the account empty to install for the current account; a specified account uses sudo and requires appropriate privileges. Duplicate detection ignores comments and preserves restrictions on existing authorized_keys entries. Only the public key is embedded, encoded as base64 to keep the clipboard command ASCII-only; the server decodes it as UTF-8. The server needs awk, tail and base64.

“Delete key” moves the selected local pair (or public-only file) to the system Trash after a native confirmation listing the exact paths. Hardware-token credentials, server authorized_keys, SSH config and copies in other apps are retained. Changed files, links and unrelated private-file formats are rejected. Trash errors never trigger permanent deletion; partial failures are reported explicitly and the list is refreshed.

OpenSSH algorithm support is separate from optional physical device discovery through libfido2. Real FIDO2 enrollment, server deployment, Linux/macOS packages and PAM/TOTP require separate verification. The 2FA checklist must be adapted to the server's existing PAM stack and tested with recovery access. Secrets are transient; JavaScript cannot guarantee erasure of immutable strings from RAM. Cancellation may leave a resident credential on the token. Deployment commands normalize line endings and skip installed keys while preserving existing restrictions; concurrent installations are not synchronized. This version does not support private-key export, SSH certificates or agent/resident-credential management.

Windows builds include key-generation utilities from [Microsoft OpenSSH 10.0.0.0p2 Preview](https://github.com/PowerShell/Win32-OpenSSH/releases/tag/10.0.0.0p2-Preview), with a pinned archive SHA256, verified Microsoft signatures and included licenses. The first Windows build requires internet access; cached tools stay outside the repository in `../verification/tools/`. System OpenSSH remains unchanged and handles SSH connections. PIN/touch confirmation uses the Windows Security dialog. This avoids Windows OpenSSH 9.5's unconditional resident-overwrite prompt, which can end in misleading `bad permissions` even for a new credential. KeyForge always refuses token overwrites, and resident keys use a filename-specific `ssh:keyforge:` application scope. Full hardware enrollment/signing still require the user's local PIN and touch.

## References

- [Electron security checklist](https://www.electronjs.org/docs/latest/tutorial/security/)
- [OpenSSH ssh-keygen options](https://man.openbsd.org/ssh-keygen.1)
- [OpenSSH authentication methods](https://man.openbsd.org/sshd_config.5)
- [Google Authenticator PAM documentation](https://github.com/google/google-authenticator-libpam)
