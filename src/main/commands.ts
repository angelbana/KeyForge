import type { GenerateRequest, Server } from "../shared/types";
import { hasTerminalControls, parsePublicKey } from "./parsers";
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
    hasTerminalControls(request.comment) ||
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
    if (request.resident)
      args.push(
        "-O",
        "resident",
        "-O",
        `application=ssh:keyforge:${request.name}`,
      );
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
export function serverInstallCommand(publicKey: string, user: string): string {
  if (
    typeof user !== "string" ||
    (user !== "" && !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(user))
  )
    throw new Error("invalidHost");
  const key = publicKey.trim();
  const { type } = parsePublicKey(key);
  const blob = key.split(/\s+/)[1];
  const script = `set -eu
umask 077
command -v awk >/dev/null
command -v tail >/dev/null
command -v base64 >/dev/null
key=$(printf '%s' ${sh(Buffer.from(key, "utf8").toString("base64"))} | base64 -d)
ssh_dir="$HOME/.ssh"
authorized="$ssh_dir/authorized_keys"
if [ -L "$ssh_dir" ] || [ -L "$authorized" ]; then
  printf '%s\\n' 'Refusing symbolic links in the SSH destination.' >&2
  exit 1
fi
mkdir -p "$ssh_dir"
[ ! -e "$authorized" ] || [ -f "$authorized" ]
chmod 700 "$ssh_dir"
touch "$authorized"
chmod 600 "$authorized"
if ! awk -v type=${sh(type)} -v blob=${sh(blob)} '/^[[:space:]]*#/ {next} {for (i=1; i<NF; i++) if ($i==type && $(i+1)==blob) found=1} END {exit !found}' "$authorized"; then
  if [ -s "$authorized" ]; then
    last_byte=$(tail -c 1 "$authorized" && printf '.')
    if [ "$last_byte" != "$(printf '\\n.')" ]; then
      printf '\\n' >> "$authorized"
    fi
  fi
  printf '%s\\n' "$key" >> "$authorized"
fi`;
  return `${user ? `sudo -u ${sh(user)} -H ` : ""}sh -c ${sh(script)}`;
}
