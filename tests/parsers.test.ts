import { configHostBlock } from "../src/shared/config";
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash } from "node:crypto";
import {
  parsePublicKey,
  privateEncryption,
  parseConfig,
} from "../src/main/parsers";
import { en, ru } from "../src/renderer/i18n";

function field(value: Buffer | string) {
  const data = Buffer.from(value);
  const size = Buffer.alloc(4);
  size.writeUInt32BE(data.length);
  return Buffer.concat([size, data]);
}
function fixture() {
  const { publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  const data = Buffer.concat([
    field("ssh-ed25519"),
    field(Buffer.from(jwk.x!, "base64url")),
  ]);
  return {
    data,
    text: `ssh-ed25519 ${data.toString("base64")} user with spaces`,
  };
}
test("public parser handles CRLF and comments with spaces", () => {
  const { data, text } = fixture();
  const key = parsePublicKey(`${text}\r\n`);
  assert.equal(key.bits, 256);
  assert.equal(key.comment, "user with spaces");
  assert.equal(
    key.fingerprint,
    `SHA256:${createHash("sha256").update(data).digest("base64").replace(/=+$/, "")}`,
  );
});
test("public parser rejects a mismatched embedded algorithm", () => {
  const { text } = fixture();
  assert.throws(
    () => parsePublicKey(text.replace(/^ssh-ed25519/, "ssh-rsa")),
    /invalidPublicKey/,
  );
});
test("public parser rejects truncated and oversized SSH fields", () => {
  for (const data of [
    Buffer.from([0, 0, 0]),
    Buffer.from([255, 255, 255, 255]),
  ])
    assert.throws(() =>
      parsePublicKey(`ssh-ed25519 ${data.toString("base64")}`),
    );
});
test("public parser rejects extra wire data and multiline injection", () => {
  const { text, data } = fixture();
  assert.throws(() => parsePublicKey(`${text}\nHost evil`));
  assert.throws(() =>
    parsePublicKey(
      `ssh-ed25519 ${Buffer.concat([data, Buffer.from([1])]).toString("base64")}`,
    ),
  );
});
test("hardware keys require application field", () => {
  const type = "sk-ssh-ed25519@openssh.com";
  const data = Buffer.concat([field(type), field(Buffer.alloc(32))]);
  assert.throws(() => parsePublicKey(`${type} ${data.toString("base64")}`));
  assert.equal(
    parsePublicKey(
      `${type} ${Buffer.concat([data, field("ssh:")]).toString("base64")}`,
    ).bits,
    256,
  );
});
test("private format detection returns unknown for corrupt data", () => {
  assert.equal(privateEncryption("not a key"), null);
  assert.equal(
    privateEncryption(
      "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
    ),
    null,
  );
});
test("encryption detection reads OpenSSH cipher metadata only", () => {
  for (const cipher of ["none", "aes256-ctr"]) {
    const header = Buffer.concat([
      Buffer.from("openssh-key-v1\0"),
      field(cipher),
    ]);
    assert.equal(
      privateEncryption(
        `-----BEGIN OPENSSH PRIVATE KEY-----\n${header.toString("base64")}\n-----END OPENSSH PRIVATE KEY-----`,
      ),
      cipher !== "none",
    );
  }
});
test("PEM encryption metadata distinguishes encrypted PKCS8", () => {
  assert.equal(
    privateEncryption("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    true,
  );
  assert.equal(privateEncryption("-----BEGIN PRIVATE KEY-----"), false);
});
test("SSH config parsing handles CRLF, equals, comments and aliases", () => {
  const hosts = parseConfig(
    '# global\r\nHost first second\r\n HostName=example.test # note\r\n User deploy\r\n Port 2222\r\n IdentityFile "~/.ssh/a"\r\nHost *\r\n User default',
  );
  assert.equal(hosts.length, 2);
  assert.equal(hosts[0].aliases, "first second");
  assert.equal(hosts[0].hostName, "example.test");
  assert.equal(hosts[0].port, "2222");
  assert.equal(hosts[1].user, "default");
});
test("config parser respects first directive and stops at Match", () => {
  const hosts = parseConfig(
    "Host test\nUser first\nUser second\nMatch user other\nUser hidden",
  );
  assert.equal(hosts[0].user, "first");
});
test("visual Host block rejects newline injection", () => {
  assert.throws(() =>
    configHostBlock({
      aliases: "test",
      hostName: "example.test\nProxyCommand evil",
      user: "user",
      port: "22",
      identityFile: "~/.ssh/key",
    }),
  );
});
test("Russian and English dictionaries have identical keys", () => {
  assert.deepEqual(Object.keys(ru).sort(), Object.keys(en).sort());
  assert.ok(Object.values(ru).every(Boolean));
});
test("quoted IdentityFile comments are preserved", () => {
  const hosts = parseConfig(
    'Host example\n IdentityFile "~/.ssh/file # label" # outside\n',
  );
  assert.equal(hosts[0].identityFile, '"~/.ssh/file # label"');
});
