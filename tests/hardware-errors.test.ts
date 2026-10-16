import { test } from "node:test";
import assert from "node:assert/strict";
import { hardwareEnrollmentFailure } from "../src/main/hardware";

test("provider failure is retained when OpenSSH also reports invalid format", () => {
  assert.equal(
    hardwareEnrollmentFailure(
      'Provider "missing.dll" dlopen failed: module not found\r\nKey enrollment failed: invalid format',
    ),
    "hardwareProviderUnavailable",
  );
  assert.equal(
    hardwareEnrollmentFailure("No FIDO SecurityKeyProvider specified"),
    "hardwareProviderUnavailable",
  );
  assert.equal(
    hardwareEnrollmentFailure("internal security key support not enabled"),
    "hardwareProviderUnavailable",
  );
});
test("enrollment diagnostics distinguish device, unsupported options and PIN states", () => {
  for (const [output, expected] of [
    ["Key enrollment failed: device not found", "hardwareDeviceUnavailable"],
    [
      "Key enrollment failed: requested feature not supported",
      "hardwareUnsupported",
    ],
    ["FIDO_ERR_UNSUPPORTED_ALGORITHM", "hardwareUnsupported"],
    ["FIDO_ERR_PIN_NOT_SET", "hardwarePinRequired"],
    ["FIDO_ERR_PIN_INVALID", "hardwarePinInvalid"],
    ["FIDO_ERR_PIN_AUTH_BLOCKED", "hardwarePinBlocked"],
    ["Key enrollment failed: invalid format", "hardwareEnrollmentFormatError"],
  ])
    assert.equal(hardwareEnrollmentFailure(output), expected);
});
test("ordinary PIN prompts and unrecognized terminal data are not diagnoses", () => {
  for (const output of [
    "Enter PIN for authenticator:",
    "You may need to touch your authenticator",
    "unrecognized output",
  ])
    assert.equal(hardwareEnrollmentFailure(output), undefined);
});
