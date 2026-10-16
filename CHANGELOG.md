# Changelog

## 0.1.7

- Recognized OpenSSH's FIDO `bad permissions` error and added actionable access guidance instead of the generic enrollment message.
- Showed actual Windows administrator status in the hardware-key form, without forcing elevation or changing token security options.

## 0.1.6

- Stopped adding blank lines before installed public keys. A separator is added only when an existing authorized_keys file lacks a final newline; existing entries and spacing are preserved.

## 0.1.5

- Added an explicit Show/Hide control for generated or entered passphrases, with automatic masking on blur, navigation and submission.
- Explained software-key encryption, hardware key-handle encryption and the separate FIDO2 PIN in both interface languages.
- Added a reminder to save generated passphrases before submitting; clarified the unencrypted hardware-handle consent.

## 0.1.4

- Replaced generic hardware enrollment failures with safe, localized FIDO provider, device, feature and PIN diagnostics.
- Kept raw terminal output and PINs inside the system process; hardware failures do not silently change algorithms or weaken verification.

## 0.1.3

- Restored softer sidebar navigation with more spacing, a subtle active tint and an accent edge.
- Improved language and theme selectors with comfortable sizing and modest rounded corners.

## 0.1.2

- Added Obsidian Monolith (default), Tokyo Night Terminal, Paper & Ink and Solarized Machining themes with a saved selection.
- Reworked the interface into a compact key table and inspector with functional borders, system UI typography and monospace metadata.
- Added paired SHA256 fingerprint display, a four-segment passphrase indicator, inline copy confirmation and Ctrl/Command+C/K shortcuts.
- Added optional libfido2 device enumeration and an OpenSSH touch-request indicator, with an explicit unknown status when detection is unavailable.

## 0.1.1

- Added a key explorer button to prepare and copy a command for installation directly on a server.
- Supports the current account or another account through sudo, safe quoting and duplicate detection that preserves existing key restrictions.

## 0.1.0

- Russian and English desktop interface.
- Public key explorer and local OpenSSH key generation.
- FIDO2 enrollment options and interactive authentication prompts.
- PowerShell/POSIX deployment helpers and optional ssh-copy-id.
- SSH config editor with safe validation, backups and conflict detection.
- Cross-platform build configuration, CI and isolated tests.
