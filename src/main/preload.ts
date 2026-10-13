import { contextBridge, ipcRenderer } from "electron";
import type { Api, Prompt } from "../shared/types";
const api: Api = {
  scan: () => ipcRenderer.invoke("keyforge:scan"),
  capabilities: () => ipcRenderer.invoke("keyforge:capabilities"),
  hardwareState: () => ipcRenderer.invoke("keyforge:hardwareState"),
  onHardwareState: (handler) => {
    const listener = (
      _event: unknown,
      state: import("../shared/types").HardwareState,
    ) => handler(state);
    ipcRenderer.on("keyforge:hardwareState", listener);
    return () => ipcRenderer.removeListener("keyforge:hardwareState", listener);
  },
  copyPublic: (name) => ipcRenderer.invoke("keyforge:copyPublic", name),
  serverCommand: (name, user) =>
    ipcRenderer.invoke("keyforge:serverCommand", name, user),
  copyServerCommand: (name, user) =>
    ipcRenderer.invoke("keyforge:copyServerCommand", name, user),
  generate: (request) => ipcRenderer.invoke("keyforge:generate", request),
  chooseTarget: (name) => ipcRenderer.invoke("keyforge:chooseTarget", name),
  cancel: () => ipcRenderer.invoke("keyforge:cancel"),
  answerPrompt: (id, answer) =>
    ipcRenderer.invoke("keyforge:answerPrompt", id, answer),
  onPrompt: (handler) => {
    const listener = (_event: unknown, prompt: Prompt) => handler(prompt);
    ipcRenderer.on("keyforge:prompt", listener);
    return () => {
      ipcRenderer.removeListener("keyforge:prompt", listener);
    };
  },
  repairPermissions: (name) =>
    ipcRenderer.invoke("keyforge:repairPermissions", name),
  config: () => ipcRenderer.invoke("keyforge:config"),
  saveConfig: (text, revision) =>
    ipcRenderer.invoke("keyforge:saveConfig", text, revision),
  validateConfig: (text) => ipcRenderer.invoke("keyforge:validateConfig", text),
  resolveHost: (alias) => ipcRenderer.invoke("keyforge:resolveHost", alias),
  snippets: (server) => ipcRenderer.invoke("keyforge:snippets", server),
  copySnippet: (server, shell) =>
    ipcRenderer.invoke("keyforge:copySnippet", server, shell),
  deploy: (server) => ipcRenderer.invoke("keyforge:deploy", server),
};
contextBridge.exposeInMainWorld("keyforge", api);
