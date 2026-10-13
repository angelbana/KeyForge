import type { GenerateRequest, Server } from "../shared/types";
export function validateName(name: string): void {
  if (
    typeof name !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(name) ||
    /\.pub$/i.test(name) ||
    /^(config|known_hosts|authorized_keys)(\.|$)/i.test(name) ||
    /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i.test(name) ||
    name.endsWith(".")
  )
    throw new Error("invalidName");
}
export function generationArgs(
  request: GenerateRequest,
  path: string,
): string[] {
  validateName(request.name);
  if (
    !["ed25519", "ecdsa", "rsa", "ed25519-sk", "ecdsa-sk"].includes(
      request.algorithm,
    )
  )
    throw new Error("invalidAlgorithm");
  if (
    typeof request.comment !== "string" ||
    request.comment.length > 256 ||
    /[\r\n\0]/.test(request.comment) ||
    typeof request.passphrase !== "string" ||
    request.passphrase.length > 1024 ||
    /[\r\n\0]/.test(request.passphrase)
  )
    throw new Error("invalidInput");
  if (
    typeof request.resident !== "boolean" ||
    typeof request.verifyRequired !== "boolean"
  )
    throw new Error("invalidInput");
  const args = ["-t", request.algorithm, "-C", request.comment, "-f", path];
  if (request.algorithm === "rsa") {
    if (![3072, 4096].includes(request.bits)) throw new Error("invalidBits");
    args.push("-b", String(request.bits));
  }
  if (request.algorithm === "ecdsa") {
    if (![256, 384, 521].includes(request.bits)) throw new Error("invalidBits");
    args.push("-b", String(request.bits));
  }
  if (request.algorithm.endsWith("-sk")) {
    if (request.resident) args.push("-O", "resident");
    if (request.verifyRequired) args.push("-O", "verify-required");
  } else if (request.resident || request.verifyRequired)
    throw new Error("invalidAlgorithm");
  return args;
}
export function validateServer(server: Server): void {
  if (
    typeof server.host !== "string" ||
    !/^[A-Za-z0-9.:[\]_-]{1,253}$/.test(server.host) ||
    server.host.startsWith("-") ||
    typeof server.user !== "string" ||
    !/^[A-Za-z0-9._-]{1,64}$/.test(server.user) ||
    server.user.startsWith("-") ||
    !Number.isInteger(server.port) ||
    server.port < 1 ||
    server.port > 65535
  )
    throw new Error("invalidHost");
  validateName(server.keyName);
}
const remoteInstall =
  "umask 077; mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys";
const sh = (value: string) => `'${value.replace(/'/g, `'"'"'`)}'`;
const ps = (value: string) => `'${value.replace(/'/g, "''")}'`;
export function deploymentSnippets(server: Server) {
  validateServer(server);
  const target = `${server.user}@${server.host}`;
  return {
    posix: `cat "$HOME/.ssh/${server.keyName}.pub" | ssh -p ${server.port} ${sh(target)} ${sh(remoteInstall)}`,
    powershell: `& { $OutputEncoding = [System.Text.UTF8Encoding]::new($false); Get-Content -LiteralPath (Join-Path $env:USERPROFILE '.ssh/${server.keyName}.pub') -Encoding UTF8 -Raw | ssh -p ${server.port} ${ps(target)} ${ps(remoteInstall)} }`,
  };
}
