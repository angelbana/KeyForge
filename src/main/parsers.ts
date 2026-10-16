import { createHash } from "node:crypto";
import type { HostEntry } from "../shared/types";
export function hasTerminalControls(value: string): boolean {
  return Array.from(value).some((char) => {
    const code = char.charCodeAt(0);
    return code < 32 || (code >= 127 && code <= 159);
  });
}

class Reader {
  offset = 0;
  constructor(private data: Buffer) {}
  field(): Buffer {
    if (this.offset + 4 > this.data.length) throw new Error("invalidPublicKey");
    const size = this.data.readUInt32BE(this.offset);
    this.offset += 4;
    if (size > this.data.length - this.offset)
      throw new Error("invalidPublicKey");
    const value = this.data.subarray(this.offset, this.offset + size);
    this.offset += size;
    return value;
  }
}
export function parsePublicKey(text: string) {
  const line = text
    .replace(/^\uFEFF/, "")
    .replace(/\r?\n$/, "")
    .replace(/^[ \t]+|[ \t]+$/g, "");
  if (hasTerminalControls(line.replace(/\t/g, "")))
    throw new Error("invalidPublicKey");
  const match = line.match(
    /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[ \t]+([A-Za-z0-9+/]+={0,2})(?:[ \t]+([^\r\n]*))?$/,
  );
  if (!match) throw new Error("invalidPublicKey");
  const [, type, encoded, comment = ""] = match;
  if (hasTerminalControls(comment)) throw new Error("invalidPublicKey");
  const data = Buffer.from(encoded, "base64");
  if (data.toString("base64").replace(/=+$/, "") !== encoded.replace(/=+$/, ""))
    throw new Error("invalidPublicKey");
  const reader = new Reader(data);
  if (reader.field().toString() !== type) throw new Error("invalidPublicKey");
  let bits: number;
  if (type === "ssh-rsa") {
    const exponent = reader.field();
    const modulus = reader.field();
    if (!exponent.length || !modulus.length || modulus[0] & 128)
      throw new Error("invalidPublicKey");
    let offset = 0;
    while (offset < modulus.length && modulus[offset] === 0) offset++;
    if (offset === modulus.length) throw new Error("invalidPublicKey");
    bits =
      (modulus.length - offset - 1) * 8 + (32 - Math.clz32(modulus[offset]));
  } else if (type.includes("ed25519")) {
    if (reader.field().length !== 32) throw new Error("invalidPublicKey");
    bits = 256;
  } else {
    const curve = reader.field().toString();
    if (!type.includes(curve) || !/^nistp(256|384|521)$/.test(curve))
      throw new Error("invalidPublicKey");
    bits = Number(curve.slice(5));
    const point = reader.field();
    if (point[0] !== 4 || point.length !== 1 + 2 * Math.ceil(bits / 8))
      throw new Error("invalidPublicKey");
  }
  if (type.startsWith("sk-") && !reader.field().length)
    throw new Error("invalidPublicKey");
  if (reader.offset !== data.length) throw new Error("invalidPublicKey");
  return {
    type,
    bits,
    comment,
    fingerprint: `SHA256:${createHash("sha256").update(data).digest("base64").replace(/=+$/, "")}`,
  };
}
export function privateEncryption(text: string): boolean | null {
  if (
    text.includes("-----BEGIN ENCRYPTED PRIVATE KEY-----") ||
    /Proc-Type:\s*4,ENCRYPTED/.test(text)
  )
    return true;
  if (text.includes("-----BEGIN OPENSSH PRIVATE KEY-----")) {
    try {
      const encoded = text
        .split("-----BEGIN OPENSSH PRIVATE KEY-----")[1]
        .split("-----END OPENSSH PRIVATE KEY-----")[0]
        .replace(/\s/g, "");
      const data = Buffer.from(encoded, "base64");
      if (data.subarray(0, 15).toString() !== "openssh-key-v1\0") return null;
      return new Reader(data.subarray(15)).field().toString() !== "none";
    } catch {
      return null;
    }
  }
  if (/-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/.test(text)) return false;
  return null;
}
function stripConfigComment(value: string): string {
  let quote = "";
  for (let index = 0; index < value.length; index++) {
    const char = value[index];
    if (char === "\\") {
      index++;
      continue;
    }
    if (char === '"' || char === "'") {
      if (!quote) quote = char;
      else if (quote === char) quote = "";
    } else if (
      char === "#" &&
      !quote &&
      (index === 0 || /\s/.test(value[index - 1]))
    )
      return value.slice(0, index).trimEnd();
  }
  return value;
}
export function parseConfig(text: string): HostEntry[] {
  const hosts: HostEntry[] = [];
  let current: HostEntry | undefined;
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z]+)(?:\s*=\s*|\s+)(.*?)\s*$/);
    if (!match || line.trim().startsWith("#")) continue;
    const key = match[1].toLowerCase(),
      value = stripConfigComment(match[2]);
    if (key === "host") {
      current = {
        aliases: value,
        hostName: "",
        user: "",
        port: "",
        identityFile: "",
      };
      hosts.push(current);
    } else if (key === "match") current = undefined;
    else if (current) {
      const field = (
        {
          hostname: "hostName",
          user: "user",
          port: "port",
          identityfile: "identityFile",
        } as const
      )[key as "hostname"];
      if (field && !current[field]) current[field] = value;
    }
  }
  return hosts;
}
