import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { promises as fs, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { serverInstallCommand } from "../src/main/commands";

function publicKey(comment = "test-local") {
  const { publicKey } = generateKeyPairSync("ed25519");
  const raw = Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url");
  const field = (value: Buffer) => {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(value.length);
    return Buffer.concat([length, value]);
  };
  const blob = Buffer.concat([
    field(Buffer.from("ssh-ed25519")),
    field(raw),
  ]).toString("base64");
  return `ssh-ed25519 ${blob} ${comment}`;
}
const shell =
  process.platform === "win32"
    ? "C:/Program Files/Git/bin/bash.exe"
    : "/bin/sh";
const shellOptions = {
  skip: !existsSync(shell) ? "POSIX shell unavailable" : false,
};
test("server command rejects usernames that inject commands or sudo options", () => {
  const key = publicKey();
  for (const user of [
    "-root",
    "a;command",
    "$(command)",
    "user\ncommand",
    "a/b",
    "a b",
  ])
    assert.throws(() => serverInstallCommand(key, user), /invalidHost/);
  assert.ok(
    serverInstallCommand(key, "deploy").startsWith(
      "sudo -u 'deploy' -H sh -c ",
    ),
  );
});
test("server command rejects malformed or multiline public keys", () => {
  assert.throws(
    () => serverInstallCommand("not a key", ""),
    /invalidPublicKey/,
  );
  assert.throws(
    () => serverInstallCommand(`${publicKey()}\ncommand`, ""),
    /invalidPublicKey/,
  );
});
test(
  "server command runs safely, preserves entries and avoids duplicates even with changed comments",
  shellOptions,
  async () => {
    const directory = await fs.mkdtemp(join(tmpdir(), "keyforge-install-"));
    try {
      const key = publicKey(
        "quotes ' and $(touch INJECTION) `touch INJECTION` Unicode: ключ",
      );
      const command = serverInstallCommand(key, "");
      // Replace only the destination HOME expression, so the actual generated shell
      // runs against a temporary directory without changing the user's environment.
      const isolated = (value: string) =>
        value.replace("$HOME/.ssh", `${directory.replace(/\\/g, "/")}/.ssh`);
      const execute = (value: string) => {
        const result = spawnSync(shell, ["-c", isolated(value)], {
          cwd: directory,
          encoding: "utf8",
          timeout: 10000,
        });
        assert.equal(
          result.status,
          0,
          "Generated command must exit successfully",
        );
      };
      execute(command);
      const authorized = join(directory, ".ssh", "authorized_keys");
      assert.equal(await fs.readFile(authorized, "utf8"), `${key}\n`);
      assert.equal(existsSync(join(directory, "INJECTION")), false);
      execute(
        serverInstallCommand(
          key.split(/\s+/).slice(0, 2).join(" ") + " changed comment",
          "",
        ),
      );
      assert.equal(await fs.readFile(authorized, "utf8"), `${key}\n`);
      const restricted = `restrict ${key}`;
      await fs.writeFile(authorized, restricted); // Also checks files without a final newline.
      execute(command);
      assert.equal(await fs.readFile(authorized, "utf8"), restricted);
      const other = publicKey("second");
      execute(serverInstallCommand(other, ""));
      assert.equal(
        await fs.readFile(authorized, "utf8"),
        `${restricted}\n${other}\n`,
      );
      const third = publicKey("third");
      execute(serverInstallCommand(third, ""));
      assert.equal(
        await fs.readFile(authorized, "utf8"),
        `${restricted}\n${other}\n${third}\n`,
      );
      // Preserve a pre-existing separator rather than editing existing content.
      await fs.writeFile(authorized, `${restricted}\n\n`);
      execute(serverInstallCommand(other, ""));
      assert.equal(
        await fs.readFile(authorized, "utf8"),
        `${restricted}\n\n${other}\n`,
      );
      if (process.platform !== "win32") {
        assert.equal(
          (await fs.stat(join(directory, ".ssh"))).mode & 0o777,
          0o700,
        );
        assert.equal((await fs.stat(authorized)).mode & 0o777, 0o600);
      }
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  },
);
