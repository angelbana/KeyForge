# KeyForge

Локальное десктопное приложение для SSH-ключей и конфигурации. Electron, React, TypeScript и Tailwind CSS. Интерфейс на русском и английском; язык переключается в боковой панели и сохраняется локально.

## Возможности

- Обзор `.pub` в стандартном каталоге SSH: алгоритм, размер, комментарий, SHA256 fingerprint, дата изменения, наличие приватного файла и его шифрования.
- Копирование только публичного ключа. Содержимое приватных ключей не передаётся в интерфейс, буфер обмена или журналы.
- Генерация через OpenSSH: Ed25519, ECDSA 256/384/521, RSA 3072/4096, ed25519-sk и ecdsa-sk. RSA 2048 не создаётся.
- Парольная фраза с ориентировочной оценкой длины и криптографическим генератором. Передача через псевдотерминал, без секретов в аргументах процесса. Пустая фраза требует явного согласия в интерфейсе.
- Выбор другого пути через системный диалог. Нельзя перезаписать существующую пару; ключи из других каталогов не входят в стандартный обзор.
- Для FIDO2: `resident`, `verify-required`, запрос PIN, ожидание касания, отмена и тайм-аут. Приложение определяет поддержку алгоритмов OpenSSH, а не подключение устройства.
- Команды установки публичного ключа для PowerShell/POSIX; интерактивный `ssh-copy-id` на Linux/macOS, если он установлен.
- Редактор SSH config с визуальным добавлением Host, сохранением исходного текста, резервной копией, проверкой конфликтов и `ssh -G`.
- Справочник SSH + TOTP для Ubuntu/Debian. Это инструкции для администратора, а не автоматическое изменение PAM.

## Запуск и сборка

Требуются Node.js 24, npm и клиент OpenSSH (`ssh`, `ssh-keygen`) в PATH. На Windows рекомендуется встроенный OpenSSH. В Linux для сборки node-pty могут понадобиться Python 3, make и C++ compiler; для запуска Electron нужны стандартные библиотеки Chromium. Сборку установщика выполняйте на целевой ОС.

```powershell
cd D:/Projects/KeyForge/git
npm ci
npm run dev
```

```sh
npm run check         # ESLint, tests, TypeScript, production frontend
npm run smoke         # Real Electron/OpenSSH in an isolated temporary directory
npm run pack          # Unpacked desktop application
npm run dist          # Windows NSIS / Linux AppImage+deb / macOS DMG
```

Исходники находятся в `git/`. Пакеты создаются в соседнем `build/packages/`, отчёты smoke-теста — в `verification/`. Компиляция создаёт игнорируемый `git/dist/`, который нужен Electron; он не коммитится. Для локальной сборки с уже установленным Electron можно выполнить:

```sh
npm exec electron-builder -- --dir --config.electronDist=node_modules/electron/dist --config.win.signAndEditExecutable=false
```

Эта команда создаёт неподписанное Windows-приложение и пропускает изменение ресурсов EXE. Обычная `npm run dist` использует стандартный процесс упаковки. Для публичных релизов настройте подписи через защищённые настройки CI.

## Безопасность и ограничения

Все ключи обрабатываются локально. Основной процесс запускает OpenSSH без shell-интерполяции. Renderer изолирован, работает без Node.js, с sandbox и CSP, без сетевых запросов; IPC проверяет окно и frame отправителя. Приложение не предоставляет просмотр или экспорт приватных ключей.

Символические ссылки, жёсткие ссылки, специальные файлы и файлы более 1 МБ отклоняются. Создание использует отдельный staging-каталог и эксклюзивное копирование. Unix: каталог `700`, файлы пары и конфиг `600`. Windows: ACL каталога и выбранных файлов ограничивается текущим пользователем. Обзор пока показывает статус Windows ACL как «Неизвестно»; исправление прав работает отдельно. Ограничение прав каталога также применяется при выборе пользовательского пути: используйте отдельный каталог SSH.

SSH config сохраняется целиком с нормализацией CRLF → LF. Визуальное добавление ставит новый Host перед существующим текстом, чтобы wildcard-настройки не перекрывали его. Поля существующих Host редактируются в текстовом редакторе. Для безопасного `ssh -G` запрещены `Include`, `Match`, `ProxyCommand`, `LocalCommand` и `KnownHostsCommand`: такие конфиги можно читать, но проверять/сохранять их нужно доверенным внешним редактором. Проверка `ssh -G` не подтверждает сетевой handshake.

Парольные фразы и PIN не сохраняются, а вывод интерактивного OpenSSH не возвращается в UI. JavaScript не гарантирует обнуление строк в оперативной памяти; это не защита от компрометации ОС или чтения памяти процесса. Тайм-аут интерактивных операций — три минуты. При отмене staging удаляется; резидентный credential уже мог появиться на токене и требует ручного удаления. Ошибка прав после создания может оставить готовую пару: проверьте её в обзоре перед повтором.

Ручные команды установки добавляют строку в authorized_keys и могут создавать дубликаты. FIDO2, серверное развёртывание и PAM требуют проверки с реальным устройством/сервером. Их успешная работа не выводится из результатов локальных тестов. Linux/macOS сборки должны пройти CI на соответствующих ОС. Ключи без `.pub`, сертификаты OpenSSH, агент SSH и управление resident credentials не входят в эту версию.

GitHub CI проверяет три ОС и создаёт локальные пакеты, не публикует релизы. Репозиторий и ветка публикации задаются владельцем; исходный проект не содержит remote. Аудит инструментов сборки может показывать отдельные проблемы транзитивных devDependencies: смотрите `npm audit` и локальный отчёт. `npm audit --omit=dev` проверяет runtime-зависимости отдельно.

## English

KeyForge is a local SSH key manager with Russian and English UI. It uses Electron, React, strict TypeScript and Tailwind CSS. Native OpenSSH creates encrypted software keys and FIDO2 credentials; private material never enters the renderer or clipboard.

Install Node.js 24 and OpenSSH, run `npm ci`, then `npm run dev`. `npm run check` runs lint, parser/service tests, type checks and the frontend build. `npm run smoke` exercises real Electron and OpenSSH in a temporary SSH directory. `npm run pack` creates an unpacked app; `npm run dist` creates platform packages. Build on each target operating system. Linux may need native build tools for node-pty. No cloud service, telemetry or account is required.

The explorer scans the default SSH directory, displays public metadata and copies only public keys. Generation supports Ed25519, NIST ECDSA, RSA 3072/4096 and security key algorithms, with passphrase/PIN prompts through a PTY. Custom save paths require the native file dialog. Existing files cannot be replaced. Unix permissions and Windows ACLs are restricted to the current user; custom destination directories are restricted too. Windows ACL auditing is displayed as unknown.

Deployment provides PowerShell/POSIX commands and optional ssh-copy-id on Unix. The config editor preserves comments and directives, creates backups, checks revisions and uses a validated temporary snapshot for `ssh -G`. Safe validation blocks Include, Match and executable directives. Edit advanced configs in a trusted external editor. Existing Host entries are editable as text; the visual form prepends new Host blocks. No network handshake is implied by local resolution.

Hardware support detection means OpenSSH algorithm support, not device discovery. Real FIDO2 enrollment, server deployment, Linux/macOS packages and PAM/TOTP require separate verification. The 2FA checklist must be adapted to the server's existing PAM stack and tested with recovery access. Secrets are transient; JavaScript cannot guarantee erasure of immutable strings from RAM. Cancellation may leave a resident credential on the token. Manual deployment can append duplicates. This version does not support private-key export, SSH certificates or agent/resident-credential management.

## References

- [Electron security checklist](https://www.electronjs.org/docs/latest/tutorial/security/)
- [OpenSSH ssh-keygen options](https://man.openbsd.org/ssh-keygen.1)
- [OpenSSH authentication methods](https://man.openbsd.org/sshd_config.5)
- [Google Authenticator PAM documentation](https://github.com/google/google-authenticator-libpam)
