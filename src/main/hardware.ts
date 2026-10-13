import type { HardwareState } from "../shared/types";
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
