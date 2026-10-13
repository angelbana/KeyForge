import type { HostEntry } from "./types";
export function configHostBlock(host: HostEntry): string {
  if (!/^[A-Za-z0-9._-]+$/.test(host.aliases) || host.aliases.startsWith("-"))
    throw new Error("invalidHost");
  if (
    !/^[A-Za-z0-9.:[\]_-]+$/.test(host.hostName) ||
    host.hostName.startsWith("-")
  )
    throw new Error("invalidHost");
  if (
    !/^[A-Za-z0-9._-]+$/.test(host.user) ||
    !/^\d+$/.test(host.port) ||
    Number(host.port) < 1 ||
    Number(host.port) > 65535
  )
    throw new Error("invalidHost");
  if (/[\r\n\0"\\]/.test(host.identityFile)) throw new Error("invalidPath");
  return `Host ${host.aliases}\n    HostName ${host.hostName}\n    User ${host.user}\n    Port ${host.port}\n    IdentityFile "${host.identityFile}"\n`;
}
