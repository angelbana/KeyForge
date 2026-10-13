import { contextBridge, ipcRenderer } from "electron";
import type { Api, Prompt } from "../shared/types";
const api: Api = {
  scan: () => ipcRenderer.invoke("keyforge:scan"),
  capabilities: () => ipcRenderer.invoke("keyforge:capabilities"),
  copyPublic: (name) => ipcRenderer.invoke("keyforge:copyPublic", name),
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
  deploy: (server) => ipcRenderer.invoke("keyforge:deploy", server),
};
contextBridge.exposeInMainWorld("keyforge", api);
