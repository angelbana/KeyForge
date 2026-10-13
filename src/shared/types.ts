export type Algorithm = "ed25519" | "ecdsa" | "rsa" | "ed25519-sk" | "ecdsa-sk";
export interface KeyInfo {
  name: string;
  path: string;
  type: string;
  bits: number;
  comment: string;
  fingerprint: string;
  encrypted: boolean | null;
  privatePresent: boolean;
  modified: string;
  permissions: string;
}
export interface KeyScan {
  directory: string;
  keys: KeyInfo[];
  warnings: string[];
}
export interface GenerateRequest {
  algorithm: Algorithm;
  bits: number;
  name: string;
  comment: string;
  passphrase: string;
  resident: boolean;
  verifyRequired: boolean;
  targetPath?: string;
}
export interface Server {
  host: string;
  user: string;
  port: number;
  keyName: string;
}
export interface HostEntry {
  aliases: string;
  hostName: string;
  user: string;
  port: string;
  identityFile: string;
}
export interface ConfigDocument {
  text: string;
  revision: string;
  hosts: HostEntry[];
}
export interface Prompt {
  id: string;
  kind: "pin" | "password" | "hostkey";
  fingerprint?: string;
}
export interface Capabilities {
  ssh: boolean;
  keygen: boolean;
  copyId: boolean;
  securityKeyAlgorithms: string[];
  platform: string;
}
export type Result<T> = { ok: true; value: T } | { ok: false; error: string };
export interface Api {
  scan(): Promise<Result<KeyScan>>;
  capabilities(): Promise<Result<Capabilities>>;
  copyPublic(name: string): Promise<Result<void>>;
  serverCommand(name: string, user: string): Promise<Result<string>>;
  copyServerCommand(name: string, user: string): Promise<Result<string>>;
  generate(request: GenerateRequest): Promise<Result<void>>;
  chooseTarget(name: string): Promise<Result<string | null>>;
  cancel(): Promise<Result<void>>;
  answerPrompt(id: string, answer: string): Promise<Result<void>>;
  onPrompt(handler: (prompt: Prompt) => void): () => void;
  repairPermissions(name: string): Promise<Result<void>>;
  config(): Promise<Result<ConfigDocument>>;
  saveConfig(text: string, revision: string): Promise<Result<ConfigDocument>>;
  validateConfig(text: string): Promise<Result<void>>;
  resolveHost(alias: string): Promise<Result<string>>;
  snippets(
    server: Server,
  ): Promise<Result<{ powershell: string; posix: string }>>;
  deploy(server: Server): Promise<Result<void>>;
}
