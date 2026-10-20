import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
const { validateRelease, validateAssets, notes } = createRequire(
  import.meta.url,
)("../scripts/publish-release.cjs");
function fixture() {
  const hash = createHash("sha256")
    .update("public-release-fixture")
    .digest("hex");
  const artifact = {
    filename: "KeyForge-1.2.3-windows-x64.zip",
    size: 42,
    sha256: hash,
  };
  const commit = "a".repeat(40);
  const manifest = {
    version: "1.2.3",
    tag: "v1.2.3",
    ...artifact,
    signature: "NotSigned",
    sourceCommit: commit,
  };
  const report = {
    ...artifact,
    status: "completed",
    url: `https://www.virustotal.com/gui/file/${hash}`,
    stats: {
      malicious: 0,
      suspicious: 0,
      undetected: 7,
      harmless: 1,
      timeout: 2,
    },
  };
  const checksums = `${hash}  ${artifact.filename}\n`;
  return { artifact, commit, manifest, report, checksums };
}
test("release requires the completed report for exactly the final bytes and source", () => {
  const f = fixture();
  const check = (
    manifest = f.manifest,
    report = f.report,
    checksums = f.checksums,
    commit = f.commit,
  ) => validateRelease(manifest, report, f.artifact, checksums, commit);
  assert.equal(check().undetected, 7);
  assert.equal(check({ ...f.manifest, signature: "Valid" }).harmless, 1);
  for (const status of [
    "checking",
    "submitted",
    "queued",
    "in-progress",
    "verification-failed",
  ])
    assert.throws(
      () => check(f.manifest, { ...f.report, status }),
      /did not complete/,
    );
  assert.throws(
    () => check(f.manifest, { ...f.report, sha256: "b".repeat(64) }),
    /exact final artifact/,
  );
  assert.throws(
    () => check(f.manifest, { ...f.report, size: 43 }),
    /exact final artifact/,
  );
  assert.throws(
    () => check(f.manifest, { ...f.report, url: "https://evil.invalid" }),
    /exact final artifact/,
  );
  assert.throws(
    () => check({ ...f.manifest, sourceCommit: "b".repeat(40) }),
    /source commit/,
  );
  assert.throws(
    () => check({ ...f.manifest, signature: "HashMismatch" }),
    /signature state/,
  );
  assert.throws(
    () => check(f.manifest, f.report, `${f.checksums}unexpected\n`),
    /checksum file/,
  );
  assert.throws(
    () => check({ ...f.manifest, filename: "../../private.zip" }),
    /invalid version or filename/,
  );
});
test("release blocks detections, incomplete engine verdicts and errored completed reports", () => {
  const f = fixture();
  for (const stats of [
    { malicious: 1 },
    { suspicious: 1 },
    { timeout: 70 },
    { undetected: -1 },
    {},
  ])
    assert.throws(() =>
      validateRelease(
        f.manifest,
        { ...f.report, stats },
        f.artifact,
        f.checksums,
        f.commit,
      ),
    );
  assert.throws(
    () =>
      validateRelease(
        f.manifest,
        { ...f.report, error: "timed out" },
        f.artifact,
        f.checksums,
        f.commit,
      ),
    /did not complete/,
  );
  const text = notes(
    f.manifest,
    f.report,
    validateRelease(f.manifest, f.report, f.artifact, f.checksums, f.commit),
    "Changes",
  );
  assert.ok(text.includes(f.report.url));
  assert.ok(text.includes("unsigned"));
  assert.ok(text.includes("Timeout: 2"));
  assert.ok(!text.includes("file is safe"));
});
test("publication verifies GitHub digests of ZIP and checksum file before leaving draft", () => {
  const { artifact } = fixture();
  const checksumHash = createHash("sha256")
    .update("checksum-fixture")
    .digest("hex");
  const assets = [
    {
      name: artifact.filename,
      size: artifact.size,
      digest: `sha256:${artifact.sha256}`,
    },
    { name: "SHA256SUMS.txt", size: 104, digest: `sha256:${checksumHash}` },
  ];
  validateAssets(assets, artifact, checksumHash, 104);
  assert.throws(
    () => validateAssets([assets[0]], artifact, checksumHash, 104),
    /left as a draft/,
  );
  assert.throws(
    () =>
      validateAssets(
        [assets[0], { ...assets[1], digest: `sha256:${artifact.sha256}` }],
        artifact,
        checksumHash,
        104,
      ),
    /left as a draft/,
  );
  assert.throws(
    () =>
      validateAssets(
        [{ ...assets[0], size: 43 }, assets[1]],
        artifact,
        checksumHash,
        104,
      ),
    /left as a draft/,
  );
  assert.throws(
    () => validateAssets([...assets, assets[0]], artifact, checksumHash, 104),
    /left as a draft/,
  );
});
