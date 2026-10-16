import { promises as fs, constants } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve, delimiter } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import {
  generationArgs,
  validateName,
  validateServer,
  deploymentSnippets,
  serverInstallCommand,
} from "./commands";
import { parseConfig, parsePublicKey, privateEncryption } from "./parsers";
import { InteractiveRunner } from "./interactive";
import { hardwareStateFromInventory } from "./hardware";
import type {
  Capabilities,
  ConfigDocument,
  GenerateRequest,
  KeyScan,
  Prompt,
  Server,
  HardwareState,
} from "../shared/types";

export async function run(
  executable: string,
  args: string[],
  timeout = 15_000,
): Promise<string> {
  return new Promise((resolveResult, reject) => {
    const child = spawn(executable, args, {
      windowsHide: true,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "",
      size = 0,
      settled = false;
    const fail = (code: string) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        child.kill();
        reject(new Error(code));
      }
    };
    const timer = setTimeout(() => fail("operationTimeout"), timeout);
    child.stdout.on("data", (data: Buffer) => {
      size += data.length;
      if (size > 1_048_576) fail("outputLimit");
      else output += data.toString();
    });
    child.stderr.resume();
    child.on("error", () => fail("toolUnavailable"));
    child.on("close", (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        if (code === 0) resolveResult(output);
        else reject(new Error("operationFailed"));
      }
    });
  });
}
const revision = (text: string) =>
  createHash("sha256").update(text).digest("hex");
async function restrictWindows(
  path: string,
  directory: boolean,
): Promise<void> {
  const literal = `'${path.replace(/'/g, "''")}'`;
  const script = `$ErrorActionPreference = 'Stop'; $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User; $acl = New-Object System.Security.AccessControl.${directory ? "DirectorySecurity" : "FileSecurity"}; $acl.SetAccessRuleProtection($true, $false); $acl.SetOwner($sid); $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', ${directory ? "'ContainerInherit, ObjectInherit', 'None', " : ""}'Allow'); $acl.AddAccessRule($rule); [System.IO.${directory ? "Directory" : "File"}]::SetAccessControl(${literal}, $acl)`;
  await run("powershell.exe", [
    "-NoProfile",
    "-NonInteractive",
    "-EncodedCommand",
    Buffer.from(script, "utf16le").toString("base64"),
  ]);
}
export class KeyService {
  async hardwareState(): Promise<HardwareState> {
    try {
      const output = await run("fido2-token", ["-L"], 5000);
      // Require an actual vendor/product device entry; Windows Hello alone is not a token.
      return hardwareStateFromInventory(output);
    } catch {
      return "unknown";
    }
  }
  async serverCommand(name: string, user: string): Promise<string> {
    return serverInstallCommand(await this.publicText(name), user);
  }
  readonly directory: string;
  readonly interactive: InteractiveRunner;
  private configSaving = false;
  private generating = false;
  constructor(
    notify: (prompt: Prompt) => void,
    directory = join(homedir(), ".ssh"),
    interactive?: InteractiveRunner,
    notifyHardware?: (state: HardwareState) => void,
  ) {
    this.directory = resolve(directory);
    this.interactive =
      interactive || new InteractiveRunner(notify, notifyHardware);
  }
  private async ensureDirectory(): Promise<void> {
    await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
    const stat = await fs.lstat(this.directory);
    if (stat.isSymbolicLink() || !stat.isDirectory())
      throw new Error("unsafePath");
  }
  private async safeFile(name: string): Promise<string> {
    if (
      name.includes("/") ||
      name.includes("\\") ||
      name.includes("\0") ||
      name === "." ||
      name === ".."
    )
      throw new Error("invalidPath");
    const path = join(this.directory, name);
    const stat = await fs.lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink > 1)
      throw new Error("unsafePath");
    if (stat.size > 1_048_576) throw new Error("fileLimit");
    return path;
  }
  private async read(name: string): Promise<Buffer> {
    const path = await this.safeFile(name);
    const handle = await fs.open(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
    );
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink > 1 || stat.size > 1_048_576)
        throw new Error("unsafePath");
      return await handle.readFile();
    } finally {
      await handle.close();
    }
  }
  async scan(): Promise<KeyScan> {
    try {
      await fs.lstat(this.directory);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT")
        return { directory: this.directory, keys: [], warnings: [] };
      throw error;
    }
    if ((await fs.lstat(this.directory)).isSymbolicLink())
      throw new Error("unsafePath");
    const result: KeyScan = {
      directory: this.directory,
      keys: [],
      warnings: [],
    };
    const entries = await fs.readdir(this.directory);
    for (const filename of entries.filter((name) => name.endsWith(".pub"))) {
      try {
        const name = filename.slice(0, -4),
          data = await this.read(filename);
        const publicKey = parsePublicKey(data.toString("utf8"));
        let encrypted: boolean | null = null,
          privatePresent = false,
          permissions = "unknown";
        try {
          const privateData = await this.read(name);
          try {
            encrypted = privateEncryption(privateData.toString("utf8"));
            privatePresent = true;
          } finally {
            privateData.fill(0);
          }
          const stat = await fs.lstat(join(this.directory, name));
          if (process.platform !== "win32")
            permissions =
              (stat.mode & 0o077) === 0 &&
              ((await fs.stat(this.directory)).mode & 0o077) === 0
                ? "restricted"
                : "open";
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT")
            result.warnings.push("privateReadFailed");
        }
        const stat = await fs.stat(join(this.directory, filename));
        result.keys.push({
          name,
          path: join(this.directory, name),
          ...publicKey,
          encrypted,
          privatePresent,
          permissions,
          modified: stat.mtime.toISOString(),
        });
      } catch {
        result.warnings.push("publicReadFailed");
      }
    }
    result.keys.sort((a, b) => a.name.localeCompare(b.name));
    return result;
  }
  async publicText(name: string): Promise<string> {
    validateName(name);
    const text = (await this.read(`${name}.pub`)).toString("utf8").trim();
    parsePublicKey(text);
    return text;
  }
  async capabilities(): Promise<Capabilities> {
    const probe = async (tool: string, args: string[]) => {
      try {
        await run(tool, args);
        return true;
      } catch {
        return false;
      }
    };
    // ssh -V writes to stderr and exits successfully; ssh-keygen -l needs a valid fixture.
    const [ssh, algorithms] = await Promise.all([
      probe("ssh", ["-V"]),
      run("ssh", ["-Q", "key"]).catch(() => ""),
    ]);
    let keygen = false;
    const temp = await fs.mkdtemp(join(tmpdir(), "keyforge-cap-"));
    try {
      await run("ssh-keygen", [
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-f",
        join(temp, "probe"),
      ]);
      keygen = true;
    } catch {
      /* Unavailable tool; no user files touched. */
    } finally {
      await fs.rm(temp, { recursive: true, force: true });
    }
    const copyId =
      process.platform !== "win32" &&
      (
        await Promise.all(
          (process.env.PATH || "")
            .split(delimiter)
            .filter(Boolean)
            .map(async (directory) => {
              try {
                await fs.access(join(directory, "ssh-copy-id"), constants.X_OK);
                return true;
              } catch {
                return false;
              }
            }),
        )
      ).some(Boolean);
    let windowsElevated: boolean | undefined;
    if (process.platform === "win32") {
      try {
        const result = await run("powershell.exe", [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $principal = New-Object Security.Principal.WindowsPrincipal($identity); if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { '1' } else { '0' }",
        ]);
        if (result.trim() === "1") windowsElevated = true;
        else if (result.trim() === "0") windowsElevated = false;
      } catch {
        /* Informational only: Windows Hello providers may work without elevation. */
      }
    }
    return {
      ssh,
      keygen,
      copyId,
      securityKeyAlgorithms: algorithms
        .split(/\r?\n/)
        .filter((value) => value.startsWith("sk-")),
      platform: process.platform,
      windowsElevated,
    };
  }
  async generate(request: GenerateRequest): Promise<void> {
    if (this.generating) throw new Error("operationBusy");
    const args = generationArgs(request, join(this.directory, request.name));
    this.generating = true;
    let staging: string | undefined;
    try {
      await this.ensureDirectory();
      if (process.platform === "win32")
        await restrictWindows(this.directory, true);
      else await fs.chmod(this.directory, 0o700);
      for (const name of [request.name, `${request.name}.pub`]) {
        try {
          await fs.lstat(join(this.directory, name));
          throw new Error("keyExists");
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        }
      }
      staging = await fs.mkdtemp(join(this.directory, ".keyforge-"));
      await fs.chmod(staging, 0o700);
      const tempKey = join(staging, request.name);
      args[args.indexOf("-f") + 1] = tempKey;
      // Native OpenSSH owns key creation and encryption; secrets never enter argv.
      const expectedEncryption = request.passphrase.length > 0;
      let passphrase = request.passphrase;
      request.passphrase = "";
      try {
        await this.interactive.run("ssh-keygen", args, staging, passphrase);
      } finally {
        passphrase = "";
      }
      const privateData = await fs.readFile(tempKey);
      try {
        if (
          privateEncryption(privateData.toString("utf8")) !== expectedEncryption
        )
          throw new Error("invalidPrivateFormat");
      } finally {
        privateData.fill(0);
      }
      parsePublicKey(await fs.readFile(`${tempKey}.pub`, "utf8"));
      // COPYFILE_EXCL prevents replacement of a key created concurrently.
      await fs.copyFile(
        tempKey,
        join(this.directory, request.name),
        constants.COPYFILE_EXCL,
      );
      try {
        await fs.copyFile(
          `${tempKey}.pub`,
          join(this.directory, `${request.name}.pub`),
          constants.COPYFILE_EXCL,
        );
      } catch {
        await fs.unlink(join(this.directory, request.name));
        throw new Error("keyExists");
      }
      await this.repairPermissions(request.name);
    } finally {
      this.generating = false;
      if (staging) await fs.rm(staging, { recursive: true, force: true });
    }
  }
  async repairPermissions(name: string): Promise<void> {
    validateName(name);
    await this.ensureDirectory();
    const privatePath = await this.safeFile(name),
      publicPath = await this.safeFile(`${name}.pub`);
    if (process.platform === "win32") {
      await restrictWindows(this.directory, true);
      await restrictWindows(privatePath, false);
      await restrictWindows(publicPath, false);
    } else {
      await fs.chmod(this.directory, 0o700);
      await fs.chmod(privatePath, 0o600);
      await fs.chmod(publicPath, 0o600);
    }
  }
  async config(): Promise<ConfigDocument> {
    let text = "";
    try {
      text = (await this.read("config")).toString("utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    return { text, revision: revision(text), hosts: parseConfig(text) };
  }
  async validateConfig(text: string): Promise<void> {
    if (
      typeof text !== "string" ||
      Buffer.byteLength(text) > 1_048_576 ||
      text.includes("\0")
    )
      throw new Error("invalidConfig");
    // ssh -G evaluates Match exec and Include. Never execute them during validation.
    if (
      /^\s*(?:include|proxycommand|localcommand|knownhostscommand|match)\b/im.test(
        text,
      )
    )
      throw new Error("unsafeConfigValidation");
    const temp = await fs.mkdtemp(join(tmpdir(), "keyforge-config-"));
    try {
      const path = join(temp, "config");
      await fs.writeFile(path, text, { mode: 0o600 });
      await run("ssh", ["-F", path, "-G", "keyforge-validation.invalid"]);
    } finally {
      await fs.rm(temp, { recursive: true, force: true });
    }
  }
  async saveConfig(text: string, expected: string): Promise<ConfigDocument> {
    if (this.configSaving) throw new Error("operationBusy");
    this.configSaving = true;
    let temporary: string | undefined;
    try {
      await this.validateConfig(text);
      await this.ensureDirectory();
      if (process.platform === "win32")
        await restrictWindows(this.directory, true);
      const current = await this.config();
      if (current.revision !== expected) throw new Error("configConflict");
      const path = join(this.directory, "config");
      if (current.text) {
        const backup = join(
          this.directory,
          `config.backup-${Date.now()}-${randomUUID()}`,
        );
        await fs.writeFile(backup, current.text, { flag: "wx", mode: 0o600 });
        if (process.platform === "win32") await restrictWindows(backup, false);
      }
      temporary = join(this.directory, `.config-${randomUUID()}`);
      await fs.writeFile(temporary, text.replace(/\r\n/g, "\n"), {
        mode: 0o600,
        flag: "wx",
      });
      if (process.platform === "win32") await restrictWindows(temporary, false);
      if ((await this.config()).revision !== expected)
        throw new Error("configConflict");
      await fs.rename(temporary, path);
      temporary = undefined;
      if (process.platform !== "win32") await fs.chmod(path, 0o600);
      return await this.config();
    } finally {
      if (temporary) await fs.rm(temporary, { force: true });
      this.configSaving = false;
    }
  }
  async resolveHost(alias: string): Promise<string> {
    if (
      typeof alias !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(alias)
    )
      throw new Error("invalidHost");
    const { text } = await this.config();
    await this.validateConfig(text);
    // Use the validated snapshot, without system/user Includes or Match exec.
    const temp = await fs.mkdtemp(join(tmpdir(), "keyforge-resolve-"));
    try {
      const path = join(temp, "config");
      await fs.writeFile(path, text, { mode: 0o600 });
      const output = await run("ssh", ["-F", path, "-G", alias]);
      return output
        .split(/\r?\n/)
        .filter((line) => /^(hostname|user|port|identityfile) /i.test(line))
        .join("\n");
    } finally {
      await fs.rm(temp, { recursive: true, force: true });
    }
  }
  snippets(server: Server) {
    return deploymentSnippets(server);
  }
  async deploy(server: Server): Promise<void> {
    validateServer(server);
    await this.publicText(server.keyName);
    if (process.platform === "win32") throw new Error("copyIdUnavailable");
    await this.interactive.run(
      "ssh-copy-id",
      [
        "-i",
        join(this.directory, `${server.keyName}.pub`),
        "-p",
        String(server.port),
        `${server.user}@${server.host}`,
      ],
      this.directory,
    );
  }
}
