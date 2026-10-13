import { test } from "node:test";
import assert from "node:assert/strict";
import {
  themes,
  fingerprintPairs,
  passphraseLevel,
} from "../src/renderer/design";
import {
  hardwareStateFromInventory,
  requestsHardwareTouch,
} from "../src/main/hardware";
test("fingerprint grouping preserves the exact OpenSSH base64 value", () => {
  const value = "SHA256:AbCdEf0123456789+/Z";
  const groups = fingerprintPairs(value);
  assert.equal(groups.join(""), value.slice(7));
  assert.ok(groups.every((group) => group.length <= 2));
});
test("all four themes have stable identifiers", () => {
  assert.deepEqual(
    themes.map((theme) => theme.id),
    ["obsidian", "tokyo", "paper", "solarized"],
  );
});
test("passphrase indicator has four discrete length levels and an empty state", () => {
  assert.deepEqual(
    [0, 1, 11, 12, 16, 20, 64].map((length) =>
      passphraseLevel("a".repeat(length)),
    ),
    [0, 1, 1, 2, 3, 4, 4],
  );
});
test("hardware inventory distinguishes actual USB entries from no device and Windows Hello", () => {
  assert.equal(hardwareStateFromInventory(""), "absent");
  assert.equal(
    hardwareStateFromInventory(
      "windowshello: vendor=0x0000, product=0x0000 (Windows Hello)",
    ),
    "absent",
  );
  assert.equal(
    hardwareStateFromInventory(
      "/dev/hidraw5: vendor=0x1050, product=0x0402 (Yubico YubiKey FIDO)\n",
    ),
    "ready",
  );
  assert.equal(hardwareStateFromInventory("unsupported output"), "unknown");
});
test("touch indicator requires a touch request in the actual OpenSSH output", () => {
  assert.equal(
    requestsHardwareTouch(
      "You may need to touch your authenticator to authorize key generation.",
    ),
    true,
  );
  assert.equal(requestsHardwareTouch("Waiting for physical touch"), true);
  assert.equal(requestsHardwareTouch("Unable to find authenticator"), false);
  assert.equal(requestsHardwareTouch("Enter PIN for authenticator:"), false);
});
