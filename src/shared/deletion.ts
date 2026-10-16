export const deletionMessages = {
  en: {
    title: "Move local key files to Trash?",
    cancel: "Cancel",
    confirm: "Move to Trash",
    detail:
      "These local files will be moved to the system Trash. They can be restored until the Trash is emptied. Server authorized_keys, SSH configuration and copies in other apps remain unchanged.",
    hardware:
      "Only the local hardware-key handle and public file are removed. The credential on the YubiKey/FIDO2 token is retained.",
  },
  ru: {
    title: "Переместить локальные файлы ключа в корзину?",
    cancel: "Отмена",
    confirm: "В корзину",
    detail:
      "Эти локальные файлы будут перемещены в системную корзину. Их можно восстановить до очистки корзины. authorized_keys на серверах, SSH-конфигурация и копии в других приложениях сохраняются.",
    hardware:
      "Удаляются только локальный файл-ссылка на аппаратный ключ и публичный файл. Запись на YubiKey/FIDO2-токене сохраняется.",
  },
} as const;
