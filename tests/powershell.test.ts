import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { deploymentSnippets } from "../src/main/commands";

test(
  "Windows PowerShell preserves the remote script and UTF-8 through native argv/stdin",
  { skip: process.platform !== "win32" },
  async () => {
    const directory = await fs.mkdtemp(join(tmpdir(), "keyforge-powershell-"));
    try {
      const source = join(directory, "Capture.cs");
      // A local argv/stdin recorder stands in for SSH. It never opens a connection.
      await fs.writeFile(
        source,
        `using System; using System.IO; using System.Text;
class Capture { static void Main(string[] args) {
Console.InputEncoding = new UTF8Encoding(false);
string output=Environment.GetEnvironmentVariable("KEYFORGE_AUDIT_CAPTURE");
for(int i=0;i<args.Length;i++) File.WriteAllText(output+i, args[i], new UTF8Encoding(false));
File.WriteAllText(output+"stdin", Console.In.ReadToEnd(), new UTF8Encoding(false));
} }`,
      );
      const csc = join(
        process.env.SystemRoot || "C:/Windows",
        "Microsoft.NET/Framework64/v4.0.30319/csc.exe",
      );
      const compilation = spawnSync(
        csc,
        ["/nologo", `/out:${join(directory, "ssh.exe")}`, source],
        { timeout: 15000 },
      );
      assert.equal(
        compilation.status,
        0,
        "Local argument recorder must compile",
      );
      await fs.mkdir(join(directory, ".ssh"));
      const key = "ssh-ed25519 QUJD ключ от кбк 🔑";
      await fs.writeFile(join(directory, ".ssh", "test.pub"), `${key}\n`);
      const snippets = deploymentSnippets({
        host: "example.invalid",
        user: "test",
        port: 2222,
        keyName: "test",
      });
      const capture = join(directory, "argument-");
      for (const executable of ["powershell.exe", "pwsh.exe"]) {
        const result = spawnSync(
          executable,
          [
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            Buffer.from(snippets.powershell, "utf16le").toString("base64"),
          ],
          {
            env: {
              ...process.env,
              PATH: `${directory};${process.env.PATH}`,
              USERPROFILE: directory,
              KEYFORGE_AUDIT_CAPTURE: capture,
            },
            timeout: 15000,
          },
        );
        if (
          executable === "pwsh.exe" &&
          result.error &&
          (result.error as NodeJS.ErrnoException).code === "ENOENT"
        )
          continue;
        assert.equal(result.status, 0);
        assert.equal(
          await fs.readFile(`${capture}2`, "utf8"),
          "test@example.invalid",
        );
        const remote = await fs.readFile(`${capture}3`, "utf8");
        assert.ok(
          remote.includes('ssh_dir="$HOME/.ssh"'),
          "Native argv must retain the shell quotes",
        );
        assert.ok(remote.includes("printf '%s\\n' \"$key\""));
        const input = await fs.readFile(`${capture}stdin`, "utf8");
        assert.equal(input.replace(/\r\n/g, "\n").trimEnd(), key);
        const destination = join(directory, "server").replace(/\\/g, "/");
        const isolated = remote.replaceAll("$HOME/.ssh", `${destination}/.ssh`);
        assert.ok(
          !isolated.includes("$HOME/.ssh") && !isolated.includes("~/.ssh"),
        );
        const install = spawnSync(
          "C:/Program Files/Git/bin/bash.exe",
          ["-c", isolated],
          { input, encoding: "utf8", timeout: 10000 },
        );
        assert.equal(
          install.status,
          0,
          "Captured native remote script must remain executable",
        );
        assert.equal(
          await fs.readFile(
            join(destination, ".ssh", "authorized_keys"),
            "utf8",
          ),
          `${key}\n`,
        );
      }
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  },
);
