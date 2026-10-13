import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { KeyService, run } from "../src/main/service";
async function isolated(
  action: (service: KeyService, directory: string) => Promise<void>,
) {
  const directory = await fs.mkdtemp(join(tmpdir(), "keyforge-test-"));
  try {
    await action(new KeyService(() => {}, directory), directory);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
}
test("real OpenSSH key is scanned without exposing private material", async () =>
  isolated(async (service, directory) => {
    await run("ssh-keygen", [
      "-q",
      "-t",
      "ed25519",
      "-N",
      "",
      "-C",
      "test-local",
      "-f",
      join(directory, "test-key"),
    ]);
    const result = await service.scan();
    assert.equal(result.keys.length, 1);
    assert.equal(result.keys[0].encrypted, false);
    const output = await run("ssh-keygen", [
      "-l",
      "-E",
      "sha256",
      "-f",
      join(directory, "test-key.pub"),
    ]);
    assert.ok(output.includes(result.keys[0].fingerprint));
    assert.ok(!JSON.stringify(result).includes("BEGIN OPENSSH"));
    assert.ok(
      (await service.publicText("test-key")).startsWith("ssh-ed25519 "),
    );
  }));
test("config writes preserve comments, back up and detect stale revision", async () =>
  isolated(async (service, directory) => {
    const initial = await service.config();
    const text =
      "# preserved\r\nHost test\r\n HostName example.test\r\n User deploy\r\n";
    const saved = await service.saveConfig(text, initial.revision);
    assert.ok(saved.text.includes("# preserved"));
    assert.ok(!saved.text.includes("\r"));
    await service.saveConfig(`${saved.text}\n Port 2222\n`, saved.revision);
    assert.ok(
      (await fs.readdir(directory)).some((name) =>
        name.startsWith("config.backup-"),
      ),
    );
    await assert.rejects(
      service.saveConfig(text, initial.revision),
      /configConflict/,
    );
  }));
test("safe config validation rejects command execution and includes", async () =>
  isolated(async (service) => {
    for (const text of [
      'Match exec "echo evil"\n User test',
      "Include other.conf",
      "ProxyCommand command",
      "LocalCommand command",
      "KnownHostsCommand command",
    ])
      await assert.rejects(
        service.validateConfig(text),
        /unsafeConfigValidation/,
      );
    await assert.rejects(
      service.validateConfig("Host test\n TotallyInvalidOption value"),
      /operationFailed/,
    );
  }));
test(
  "scan refuses linked public files",
  {
    skip:
      process.platform === "win32"
        ? "Windows symlink creation requires extra privileges"
        : false,
  },
  async () =>
    isolated(async (service, directory) => {
      await fs.writeFile(join(directory, "target"), "data");
      await fs.symlink(
        join(directory, "target"),
        join(directory, "linked.pub"),
      );
      assert.equal((await service.scan()).keys.length, 0);
      assert.equal((await service.scan()).warnings.length, 1);
    }),
);
test("scan refuses oversized public files", async () =>
  isolated(async (service, directory) => {
    await fs.writeFile(
      join(directory, "oversize.pub"),
      Buffer.alloc(1_048_577),
    );
    const result = await service.scan();
    assert.equal(result.keys.length, 0);
    assert.equal(result.warnings.length, 1);
  }));
test("host resolution returns a small safe subset", async () =>
  isolated(async (service) => {
    const initial = await service.config();
    await service.saveConfig(
      "Host demo\n HostName example.test\n User deploy\n Port 2222\n",
      initial.revision,
    );
    const result = await service.resolveHost("demo");
    assert.ok(result.includes("hostname example.test"));
    assert.ok(result.includes("port 2222"));
    await assert.rejects(service.resolveHost("-oProxyCommand=bad"));
  }));

test("scan blocks hard-linked key files", async () =>
  isolated(async (service, directory) => {
    await run("ssh-keygen", [
      "-q",
      "-t",
      "ed25519",
      "-N",
      "",
      "-f",
      join(directory, "original"),
    ]);
    await fs.link(
      join(directory, "original.pub"),
      join(directory, "linked.pub"),
    );
    const result = await service.scan();
    assert.equal(result.keys.length, 0);
    assert.equal(result.warnings.length, 2);
  }));
test("scan blocks a linked SSH directory including Windows junctions", async () =>
  isolated(async (_service, directory) => {
    const target = join(directory, "target"),
      link = join(directory, "junction");
    await fs.mkdir(target);
    await fs.symlink(
      target,
      link,
      process.platform === "win32" ? "junction" : "dir",
    );
    await assert.rejects(new KeyService(() => {}, link).scan(), /unsafePath/);
  }));
