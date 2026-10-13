import { app, BrowserWindow, ipcMain, clipboard, Menu, dialog } from "electron";
import { join, dirname, basename, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { KeyService } from "./service";
import type { Api, GenerateRequest, Result } from "../shared/types";
import { validateName } from "./commands";

let window: BrowserWindow | undefined;
const rendererPath = join(__dirname, "../renderer/index.html");
const rendererUrl = pathToFileURL(rendererPath).href;
const service = new KeyService((prompt) =>
  window?.webContents.send("keyforge:prompt", prompt),
);
const selectedPaths = new Set<string>();
const knownErrors = new Set([
  "invalidPublicKey",
  "invalidName",
  "invalidAlgorithm",
  "invalidBits",
  "invalidInput",
  "invalidHost",
  "invalidPath",
  "unsafePath",
  "fileLimit",
  "operationBusy",
  "operationTimeout",
  "operationFailed",
  "operationCancelled",
  "toolUnavailable",
  "outputLimit",
  "invalidPrompt",
  "keyExists",
  "invalidPrivateFormat",
  "permissionsFailed",
  "invalidConfig",
  "unsafeConfigValidation",
  "configConflict",
  "copyIdUnavailable",
]);
type CommandName = Exclude<keyof Api, "onPrompt">;
function handle<K extends CommandName>(
  name: K,
  action: (...args: Parameters<Api[K]>) => unknown,
): void {
  ipcMain.handle(
    `keyforge:${name}`,
    async (event, ...args): Promise<Result<unknown>> => {
      if (
        !window ||
        event.sender !== window.webContents ||
        event.senderFrame !== window.webContents.mainFrame ||
        event.senderFrame.url !== rendererUrl
      )
        return { ok: false, error: "unauthorized" };
      try {
        return {
          ok: true,
          value: await action(...(args as Parameters<Api[K]>)),
        };
      } catch (error) {
        const code = error instanceof Error ? error.message : "";
        return {
          ok: false,
          error: knownErrors.has(code) ? code : "operationFailed",
        };
      }
    },
  );
}
app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  handle("scan", () => service.scan());
  handle("capabilities", () => service.capabilities());
  handle("copyPublic", async (name) =>
    clipboard.writeText(await service.publicText(name)),
  );
  handle("serverCommand", (name, user) => service.serverCommand(name, user));
  handle("copyServerCommand", async (name, user) => {
    const command = await service.serverCommand(name, user);
    await clipboard.writeText(command);
    return command;
  });
  handle("chooseTarget", async (name: string) => {
    validateName(name);
    const selection = await dialog.showSaveDialog(window!, {
      defaultPath: join(service.directory, name),
      title: "KeyForge",
      buttonLabel: "Select / Выбрать",
    });
    if (selection.canceled || !selection.filePath) return null;
    const path = resolve(selection.filePath);
    validateName(basename(path));
    if (selectedPaths.size > 20) selectedPaths.clear();
    selectedPaths.add(path);
    return path;
  });
  handle("generate", (request: GenerateRequest) => {
    if (request.targetPath) {
      if (
        typeof request.targetPath !== "string" ||
        !selectedPaths.delete(request.targetPath)
      )
        throw new Error("invalidPath");
      const targetService = new KeyService(
        (prompt) => window?.webContents.send("keyforge:prompt", prompt),
        dirname(request.targetPath),
        service.interactive,
      );
      return targetService.generate({
        ...request,
        name: basename(request.targetPath),
      });
    }
    return service.generate(request);
  });
  handle("cancel", () => service.interactive.cancel());
  handle("answerPrompt", (id, answer) =>
    service.interactive.answer(id, answer),
  );
  handle("repairPermissions", (name) => service.repairPermissions(name));
  handle("config", () => service.config());
  handle("saveConfig", (text, revision) => service.saveConfig(text, revision));
  handle("validateConfig", (text) => service.validateConfig(text));
  handle("resolveHost", (alias) => service.resolveHost(alias));
  handle("snippets", (server) => service.snippets(server));
  handle("deploy", (server) => service.deploy(server));
  const createWindow = () => {
    window = new BrowserWindow({
      width: 1240,
      height: 860,
      minWidth: 840,
      minHeight: 650,
      title: "KeyForge",
      icon: join(__dirname, "../assets/icon.png"),
      backgroundColor: "#f5f8fc",
      webPreferences: {
        preload: join(__dirname, "preload.js"),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
      },
    });
    window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
    window.webContents.on("will-navigate", (event) => event.preventDefault());
    window.webContents.on("will-attach-webview", (event) =>
      event.preventDefault(),
    );
    window.webContents.session.setPermissionRequestHandler(
      (_contents, _permission, callback) => callback(false),
    );
    window.on("closed", () => {
      service.interactive.cancel();
      window = undefined;
    });
    void window.loadFile(rendererPath);
  };
  createWindow();
  app.on("activate", () => {
    if (!window) createWindow();
  });
});
app.on("window-all-closed", () => {
  service.interactive.cancel();
  if (process.platform !== "darwin") app.quit();
});
