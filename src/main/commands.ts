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
    hasTerminalControls(request.passphrase)
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
const sh = (value: string) => `'${value.replace(/'/g, `'"'"'`)}'`;
const ps = (value: string) => `'${value.replace(/'/g, "''")}'`;
const installHeader = `set -eu
umask 077
LC_ALL=C
export LC_ALL
command -v awk >/dev/null
command -v tail >/dev/null`;
// Shared by clipboard commands and SSH stdin transport. Never rewrite existing entries.
const installBody = String.raw`type=$(printf '%s\n' "$key" | awk '{print $1}')
blob=$(printf '%s\n' "$key" | awk '{print $2}')
case "$type" in
  ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) ;;
  *) exit 1 ;;
esac
case "$blob" in ''|*[!A-Za-z0-9+/=]*) exit 1 ;; esac
ssh_dir="$HOME/.ssh"
authorized="$ssh_dir/authorized_keys"
if [ -L "$ssh_dir" ] || [ -L "$authorized" ]; then
  printf '%s\n' 'Refusing symbolic links in the SSH destination.' >&2
  exit 1
fi
mkdir -p "$ssh_dir"
[ ! -e "$authorized" ] || [ -f "$authorized" ]
chmod 700 "$ssh_dir"
touch "$authorized"
chmod 600 "$authorized"
installed=$(awk -v type="$type" -v blob="$blob" '
function token(    value, quoted, escaped, char) {
  value=""; quoted=0; escaped=0
  while (pos<=length(line)) {
    char=substr(line,pos++,1)
    if (escaped) { value=value char; escaped=0 }
    else if (char=="\\") { value=value char; escaped=1 }
    else if (char=="\"") { value=value char; quoted=!quoted }
    else if (char ~ /[ \t]/ && !quoted) { if (value!="") return value }
    else value=value char
  }
  return value
}
/^[[:space:]]*#/ {next}
{
  line=$0; pos=1; first=token()
  if (first==type) { if (token()==blob) found=1 }
  else if (token()==type) { if (token()==blob) found=1 }
}
END {print found ? 1 : 0}' "$authorized")
if [ "$installed" != 1 ]; then
  if [ -s "$authorized" ]; then
    last_byte=$(tail -c 1 "$authorized" && printf '.')
    if [ "$last_byte" != "$(printf '\n.')" ]; then
      printf '\n' >> "$authorized"
    fi
  fi
  printf '%s\n' "$key" >> "$authorized"
fi`;
const normalizePublicStdin = String.raw`{ if (NR==1) sub(/^\357\273\277/, ""); sub(/\r$/, ""); if ($0=="") next; check=$0; gsub(/\t/, "", check); if (check ~ /[[:cntrl:]]/ || ++lines>1) exit 1; print } END {if (lines!=1) exit 1}`;
const remoteInstall = `${installHeader}
key=$(awk ${sh(normalizePublicStdin)})
${installBody}`;
// PowerShell's legacy native argv mode consumes quotes and their preceding slashes.
const legacyNativeQuoting = String.raw`if (-not (Get-Variable PSNativeCommandArgumentPassing -ErrorAction SilentlyContinue) -or $PSNativeCommandArgumentPassing -eq 'Legacy') { $remote = [regex]::Replace($remote, '(\\*)"', '$1$1\"') };`;
export function deploymentSnippets(server: Server) {
  validateServer(server);
  const target = `${server.user}@${server.host}`;
  return {
    posix: `cat "$HOME/.ssh/${server.keyName}.pub" | ssh -p ${server.port} ${sh(target)} ${sh(remoteInstall)}`,
    powershell: `& { $OutputEncoding = [System.Text.UTF8Encoding]::new($false); $remote = ${ps(remoteInstall)}; ${legacyNativeQuoting} Get-Content -LiteralPath (Join-Path $env:USERPROFILE '.ssh/${server.keyName}.pub') -Encoding UTF8 -Raw | ssh -p ${server.port} ${ps(target)} $remote }`,
  };
}
export function serverInstallCommand(publicKey: string, user: string): string {
  if (
    typeof user !== "string" ||
    (user !== "" && !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(user))
  )
    throw new Error("invalidHost");
  const key = publicKey.trim();
  parsePublicKey(key);
  const script = `${installHeader}
command -v base64 >/dev/null
key=$(printf '%s' ${sh(Buffer.from(key, "utf8").toString("base64"))} | base64 -d)
${installBody}`;
  return `${user ? `sudo -u ${sh(user)} -H ` : ""}sh -c ${sh(script)}`;
}
