import type { HardwareState } from "../shared/types";
// Return fixed codes only: terminal output can contain paths or authentication data.
export function hardwareEnrollmentFailure(output: string): string | undefined {
  if (
    /key enrollment failed:\s*(?:bad permissions|permission denied)|FIDO_ERR_ACCESS_DENIED/i.test(
      output,
    )
  )
    return "hardwareAccessDenied";
  if (
    /provider[\s\S]{0,1024}(?:dlopen\s+failed|not found|could not|unable)|no FIDO SecurityKeyProvider specified|internal security key support not enabled|no (?:fido|security key) provider|security key provider.*(?:unavailable|not supported)/i.test(
      output,
    )
  )
    return "hardwareProviderUnavailable";
  if (
    /pin (?:is )?(?:blocked|auth blocked)|FIDO_ERR_PIN_(?:AUTH_)?BLOCKED/i.test(
      output,
    )
  )
    return "hardwarePinBlocked";
  if (/pin (?:is )?(?:not set|required)|FIDO_ERR_PIN_NOT_SET/i.test(output))
    return "hardwarePinRequired";
  if (
    /pin (?:is )?(?:invalid|incorrect)|incorrect pin|FIDO_ERR_PIN_INVALID/i.test(
      output,
    )
  )
    return "hardwarePinInvalid";
  if (
    /key enrollment failed:\s*(?:requested feature not supported|operation not supported)|FIDO_ERR_(?:UNSUPPORTED_ALGORITHM|UNSUPPORTED_OPTION)/i.test(
      output,
    )
  )
    return "hardwareUnsupported";
  if (
    /key enrollment failed:\s*(?:device not found|no device)|unable to find (?:an? )?(?:authenticator|device)|no authenticator found/i.test(
      output,
    )
  )
    return "hardwareDeviceUnavailable";
  if (/key enrollment failed:\s*invalid format/i.test(output))
    return "hardwareEnrollmentFormatError";
  return undefined;
}
export function hardwareStateFromInventory(output: string): HardwareState {
  let recognized = false;
  const device = output.split(/\r?\n/).some((line) => {
    const ids = line.match(/vendor=0x([0-9a-f]+),\s*product=0x([0-9a-f]+)/i);
    if (ids) recognized = true;
    if (/win(?:dows)?\s*hello/i.test(line)) return false;
    return !!ids && parseInt(ids[1], 16) > 0 && parseInt(ids[2], 16) > 0;
  });
  return device ? "ready" : output.trim() && !recognized ? "unknown" : "absent";
}
export function requestsHardwareTouch(output: string): boolean {
  return /touch (?:your |the )?(?:authenticator|security key)|waiting for.*touch/i.test(
    output,
  );
}
