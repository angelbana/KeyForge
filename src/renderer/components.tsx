import { fingerprintPairs, passphraseLevel } from "./design";
import type { HardwareState } from "../shared/types";
export function FingerprintBadge({ value }: { value: string }) {
  return (
    <span className="fingerprint-badge" aria-label={value} title={value}>
      <span className="fingerprint-prefix">SHA256:</span>
      <span className="fingerprint-pairs">
        {fingerprintPairs(value).map((pair, index) => (
          <span key={index}>{pair}</span>
        ))}
      </span>
    </span>
  );
}
export function StrengthIndicator({
  value,
  label,
}: {
  value: string;
  label: string;
}) {
  const level = passphraseLevel(value);
  return (
    <span
      className="strength-indicator"
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={4}
      aria-valuenow={level}
      aria-valuetext={label}
    >
      <span className="strength-segments" data-level={level}>
        {[1, 2, 3, 4].map((segment) => (
          <span key={segment} data-filled={segment <= level} />
        ))}
      </span>
      <span>{label}</span>
    </span>
  );
}
export function HardwareIndicator({
  state,
  label,
}: {
  state: HardwareState;
  label: string;
}) {
  return (
    <span className="hardware-state" role="status" data-state={state}>
      <span className="hardware-led" aria-hidden="true" />
      {label}
    </span>
  );
}
