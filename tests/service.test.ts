import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { KeyService, run } from "../src/main/service";
import { InteractiveRunner } from "../src/main/interactive";

test("process output preserves UTF-8 split across writes", async () => {
  const output = await run(process.execPath, [
    "-e",
    "process.stdout.write(Buffer.from([0xd0]));setTimeout(()=>process.stdout.write(Buffer.from([0xba])),100)",
  ]);
  assert.equal(output, "к");
});

test("cancellation during directory preparation prevents key generation", async () => {
  const directory = await fs.mkdtemp(join(tmpdir(), "keyforge-cancel-"));
  const runner = new InteractiveRunner(() => {});
  const service = new KeyService(() => {}, directory, runner);
  let release!: () => void;
  let entered!: () => void;
  const preparing = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const mkdir = fs.mkdir.bind(fs);
  const mkdirMock = mock.method(
    fs,
    "mkdir",
    async (...args: Parameters<typeof fs.mkdir>) => {
      if (args[0] === directory) {
        entered();
        await gate;
      }
      return mkdir(...args);
    },
  );
  const runMock = mock.method(runner, "run", async () => {
    throw new Error("nativeStarted");
  });
  const request = {
    algorithm: "ed25519" as const,
    bits: 256,
    name: "cancelled",
    comment: "",
    passphrase: "",
    resident: false,
    verifyRequired: false,
  };
  try {
    const result = service.generate(request);
    const rejected = assert.rejects(result, /operationCancelled/);
    await preparing;
    runner.cancel();
    release();
    await rejected;
    assert.equal(runMock.mock.callCount(), 0);
    assert.deepEqual(await fs.readdir(directory), []);
  } finally {
    release();
    mkdirMock.mock.restore();
    runMock.mock.restore();
    await fs.rm(directory, { recursive: true, force: true });
  }
});
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

async function deletionFixture(service: KeyService, directory: string) {
  await run("ssh-keygen", [
    "-q",
    "-t",
    "ed25519",
    "-N",
    "",
    "-f",
    join(directory, "delete-test"),
  ]);
  return (await service.scan()).keys[0];
}
test("pending deletion blocks duplicate deletion and key generation until canceled", async () =>
  isolated(async (service, directory) => {
    const key = await deletionFixture(service, directory);
    let enter!: () => void, release!: () => void;
    const entered = new Promise<void>((resolve) => {
      enter = resolve;
    });
    const pending = service.deleteKey(
      key.name,
      key.fingerprint,
      async () => {
        enter();
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        return false;
      },
      async () => {
        assert.fail();
      },
    );
    await entered;
    await assert.rejects(
      service.deleteKey(
        key.name,
        key.fingerprint,
        async () => true,
        async () => {
          assert.fail();
        },
      ),
      /operationBusy/,
    );
    await assert.rejects(
      new KeyService(() => {}, directory, service.interactive).generate({
        algorithm: "ed25519",
        bits: 256,
        name: "other",
        comment: "",
        passphrase: "",
        resident: false,
        verifyRequired: false,
      }),
      /operationBusy/,
    );
    release();
    assert.equal(await pending, false);
  }));
test("deletion cancel preserves both files and never invokes Trash", async () =>
  isolated(async (service, directory) => {
    const key = await deletionFixture(service, directory);
    const deleted = await service.deleteKey(
      key.name,
      key.fingerprint,
      async (plan) => {
        assert.deepEqual(plan.files, [key.path, `${key.path}.pub`]);
        assert.equal(plan.hardware, false);
        return false;
      },
      async () => {
        assert.fail("Trash must not be called without confirmation");
      },
    );
    assert.equal(deleted, false);
    await fs.access(key.path);
    await fs.access(`${key.path}.pub`);
  }));
test("confirmed deletion sends only the selected pair to an injected Trash mover", async () =>
  isolated(async (service, directory) => {
    const key = await deletionFixture(service, directory);
    await fs.writeFile(join(directory, "config"), "# keep");
    await fs.writeFile(join(directory, "authorized_keys"), "# keep");
    const trash = join(directory, "recycle");
    await fs.mkdir(trash);
    assert.equal(
      await service.deleteKey(
        key.name,
        key.fingerprint,
        async () => true,
        async (path) => {
          await fs.rename(path, join(trash, basename(path)));
        },
      ),
      true,
    );
    await assert.rejects(fs.access(key.path));
    await assert.rejects(fs.access(`${key.path}.pub`));
    assert.deepEqual((await fs.readdir(trash)).sort(), [
      key.name,
      `${key.name}.pub`,
    ]);
    assert.equal(
      await fs.readFile(join(directory, "config"), "utf8"),
      "# keep",
    );
    assert.equal(
      await fs.readFile(join(directory, "authorized_keys"), "utf8"),
      "# keep",
    );
  }));
test("deletion rejects stale fingerprints and files changed during confirmation", async () =>
  isolated(async (service, directory) => {
    const key = await deletionFixture(service, directory);
    const neverTrash = async () => {
      assert.fail("Changed files must not be trashed");
    };
    await assert.rejects(
      service.deleteKey(key.name, "stale", async () => true, neverTrash),
      /keyChanged/,
    );
    await assert.rejects(
      service.deleteKey(
        key.name,
        key.fingerprint,
        async () => {
          await fs.appendFile(key.path, "\n");
          return true;
        },
        neverTrash,
      ),
      /keyChanged/,
    );
    await fs.access(key.path);
    await fs.access(`${key.path}.pub`);
  }));
test("public-only deletion lists one file, rejects unsafe names and unrecognized private files", async () =>
  isolated(async (service, directory) => {
    const key = await deletionFixture(service, directory);
    await fs.unlink(key.path);
    assert.equal(
      await service.deleteKey(
        key.name,
        key.fingerprint,
        async (plan) => {
          assert.deepEqual(plan.files, [`${key.path}.pub`]);
          return false;
        },
        async () => {
          assert.fail();
        },
      ),
      false,
    );
    for (const name of ["../outside", "config", "authorized_keys", "x/y"])
      await assert.rejects(
        service.deleteKey(
          name,
          key.fingerprint,
          async () => true,
          async () => {
            assert.fail();
          },
        ),
        /invalidName/,
      );
    await fs.writeFile(key.path, "unrelated document");
    await assert.rejects(
      service.deleteKey(
        key.name,
        key.fingerprint,
        async () => true,
        async () => {
          assert.fail();
        },
      ),
      /invalidPrivateFormat/,
    );
  }));
test("deletion refuses linked files and directory junctions before moving anything", async () =>
  isolated(async (service, directory) => {
    const key = await deletionFixture(service, directory);
    await fs.link(key.path, join(directory, "other-link"));
    await assert.rejects(
      service.deleteKey(
        key.name,
        key.fingerprint,
        async () => true,
        async () => {
          assert.fail();
        },
      ),
      /unsafePath/,
    );
    const link = join(directory, "linked-directory");
    await fs.symlink(
      directory,
      link,
      process.platform === "win32" ? "junction" : "dir",
    );
    await assert.rejects(
      new KeyService(() => {}, link).deleteKey(
        key.name,
        key.fingerprint,
        async () => true,
        async () => {
          assert.fail();
        },
      ),
      /unsafePath/,
    );
    await fs.unlink(link);
  }));
test("Trash failure never falls back to permanent deletion and partial failure is explicit", async () =>
  isolated(async (service, directory) => {
    const key = await deletionFixture(service, directory);
    await assert.rejects(
      service.deleteKey(
        key.name,
        key.fingerprint,
        async () => true,
        async () => {
          throw new Error("trash unavailable");
        },
      ),
      /keyDeleteFailed/,
    );
    await fs.access(key.path);
    await fs.access(`${key.path}.pub`);
    let moved = 0;
    await assert.rejects(
      service.deleteKey(
        key.name,
        key.fingerprint,
        async () => true,
        async (path) => {
          if (moved++) throw new Error("locked");
          await fs.rename(path, join(directory, "recoverable-key"));
        },
      ),
      /keyDeletePartial/,
    );
    await fs.access(join(directory, "recoverable-key"));
    await fs.access(`${key.path}.pub`);
  }));
