import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  generationArgs,
  deploymentSnippets,
  validateName,
} from "../src/main/commands";
import type { GenerateRequest, Server } from "../src/shared/types";
const request: GenerateRequest = {
  algorithm: "ed25519",
  bits: 256,
  name: "test-key",
  comment: "example comment",
  passphrase: "",
  resident: false,
  verifyRequired: false,
};
const server: Server = {
  host: "example.test",
  user: "deploy",
  port: 2222,
  keyName: "test-key",
};
test("generation never places passphrase in argv", () => {
  const passphrase = randomBytes(24).toString("hex");
  const args = generationArgs(
    { ...request, passphrase },
    "C:\\Users\\Example User\\.ssh\\test-key",
  );
  assert.ok(!args.includes(passphrase));
  assert.ok(!args.includes("-N"));
  assert.equal(
    args[args.indexOf("-f") + 1],
    "C:\\Users\\Example User\\.ssh\\test-key",
  );
});
test("RSA rejects 2048 and unsupported sizes", () => {
  for (const bits of [2048, 1024, 0, 4097])
    assert.throws(
      () => generationArgs({ ...request, algorithm: "rsa", bits }, "/tmp/key"),
      /invalidBits/,
    );
});
test("ECDSA validates NIST curve sizes", () => {
  for (const bits of [256, 384, 521])
    assert.ok(
      generationArgs(
        { ...request, algorithm: "ecdsa", bits },
        "/tmp/key",
      ).includes(String(bits)),
    );
  assert.throws(() =>
    generationArgs({ ...request, algorithm: "ecdsa", bits: 4096 }, "/tmp/key"),
  );
});
test("hardware flags are limited to security key algorithms", () => {
  const args = generationArgs(
    {
      ...request,
      algorithm: "ed25519-sk",
      resident: true,
      verifyRequired: true,
    },
    "/tmp/key",
  );
  assert.ok(args.includes("resident"));
  assert.ok(args.includes("verify-required"));
  assert.throws(() =>
    generationArgs({ ...request, resident: true }, "/tmp/key"),
  );
});
test("file names reject traversal, SSH config and Windows reserved paths", () => {
  for (const name of [
    "../key",
    "a/b",
    "a\\b",
    "config",
    "known_hosts",
    "authorized_keys",
    "CON",
    "aux.txt",
    "key.pub",
    "key.",
    "-oProxyCommand",
  ])
    assert.throws(() => validateName(name));
});
test("deployment rejects shell injection and option injection", () => {
  for (const host of [
    "x; echo bad",
    "$(command)",
    "`command`",
    "-oProxyCommand=x",
    "test\ncommand",
  ])
    assert.throws(() => deploymentSnippets({ ...server, host }));
  assert.throws(() => deploymentSnippets({ ...server, port: 65536 }));
  assert.throws(() => deploymentSnippets({ ...server, user: "-root" }));
});
test("deployment quotes arguments and uses public files in both shells", () => {
  const commands = deploymentSnippets(server);
  assert.ok(commands.powershell.includes("$env:USERPROFILE"));
  assert.ok(commands.powershell.includes("-LiteralPath"));
  assert.ok(commands.posix.includes('"$HOME/.ssh/test-key.pub"'));
  assert.ok(commands.posix.includes("-p 2222"));
  assert.ok(commands.posix.includes("chmod 600"));
});
