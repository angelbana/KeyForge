const fs = require("node:fs/promises");
const path = require("node:path");
const { execFileSync, spawnSync } = require("node:child_process");
const { publicArtifact, stats } = require("./virustotal.cjs");
const ROOT = path.resolve(__dirname, "..");
const OUTPUT = path.resolve(ROOT, "../verification/ci-release");
const REPO = "angelbana/KeyForge";
function validateRelease(manifest, report, artifact, checksums, commit) {
  if (
    !/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(manifest.version) ||
    manifest.tag !== `v${manifest.version}` ||
    manifest.filename !== `KeyForge-${manifest.version}-windows-x64.zip`
  )
    throw new Error("Release manifest has an invalid version or filename.");
  if (
    manifest.sourceCommit !== commit ||
    manifest.sha256 !== artifact.sha256 ||
    manifest.size !== artifact.size ||
    manifest.filename !== artifact.filename
  )
    throw new Error(
      "Final artifact differs from its release manifest or source commit.",
    );
  if (
    manifest.signature !== "Valid" ||
    checksums !== `${artifact.sha256}  ${artifact.filename}\n`
  )
    throw new Error("Release signature state or checksum file is invalid.");
  if (
    report.status !== "completed" ||
    report.error ||
    report.sha256 !== artifact.sha256 ||
    report.filename !== artifact.filename ||
    report.size !== artifact.size ||
    report.url !== `https://www.virustotal.com/gui/file/${artifact.sha256}`
  )
    throw new Error(
      "VirusTotal did not complete analysis of this exact final artifact.",
    );
  const results = stats(report.stats);
  if (results.malicious || results.suspicious)
    throw new Error(
      "VirusTotal detections require review; release publication stopped.",
    );
  if (results.harmless + results.undetected === 0)
    throw new Error(
      "VirusTotal has no completed engine verdicts; release publication stopped.",
    );
  return results;
}
function notes(manifest, report, results, changes) {
  return `KeyForge ${manifest.version} — Windows x64\n\nDownload **${manifest.filename}**, extract the complete ZIP and run **KeyForge/KeyForge.exe**. The Windows application has a verified digital signature.\n\nVirusTotal: [отчёт для опубликованного ZIP / report for the released ZIP](${report.url}).\n\nАнализ завершён / Analysis completed. Malicious: **${results.malicious}**, suspicious: **${results.suspicious}**, undetected: **${results.undetected}**, harmless: **${results.harmless}**. Timeout: ${results.timeout + results["confirmed-timeout"]}; failure: ${results.failure}; unsupported: ${results["type-unsupported"]}.\n\nSHA256: \`${manifest.sha256}\`\n\n${changes.trim()}\n`;
}
function validateAssets(assets, artifact, checksumHash, checksumSize) {
  for (const expected of [
    { name: artifact.filename, sha256: artifact.sha256, size: artifact.size },
    { name: "SHA256SUMS.txt", sha256: checksumHash, size: checksumSize },
  ]) {
    const matches = assets.filter((value) => value.name === expected.name);
    if (
      matches.length !== 1 ||
      matches[0].size !== expected.size ||
      matches[0].digest !== `sha256:${expected.sha256}`
    )
      throw new Error(
        "Uploaded asset digest differs; release left as a draft.",
      );
  }
  if (assets.length !== 2)
    throw new Error("Unexpected release assets; release left as a draft.");
}
function gh(args, allowMissing = false) {
  const result = spawnSync("gh", args, {
    encoding: "utf8",
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status === 0) return result.stdout;
  if (
    allowMissing &&
    /(?:\(HTTP 404\)|release not found)/i.test(result.stderr || "")
  )
    return undefined;
  throw new Error(
    "GitHub release operation failed; no credentials or raw response are logged.",
  );
}
async function main() {
  const manifest = JSON.parse(
    await fs.readFile(path.join(OUTPUT, "release-manifest.json"), "utf8"),
  );
  // Validate before resolving a filename supplied by a manifest.
  if (!/^KeyForge-[A-Za-z0-9.-]+-windows-x64\.zip$/.test(manifest.filename))
    throw new Error("Invalid release filename.");
  const artifact = await publicArtifact(path.join(OUTPUT, manifest.filename), [
    OUTPUT,
  ]);
  const reportPath = path.join(OUTPUT, `${artifact.filename}.virustotal.json`);
  const report = JSON.parse(await fs.readFile(reportPath, "utf8"));
  const checksums = await fs.readFile(
    path.join(OUTPUT, "SHA256SUMS.txt"),
    "utf8",
  );
  const repoRoot = execFileSync(
    "git",
    ["-C", ROOT, "rev-parse", "--show-toplevel"],
    { encoding: "utf8" },
  ).trim();
  if (path.resolve(repoRoot).toLowerCase() !== ROOT.toLowerCase())
    throw new Error("Unexpected repository root.");
  const commit = execFileSync("git", ["-C", ROOT, "rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim();
  const results = validateRelease(
    manifest,
    report,
    artifact,
    checksums,
    commit,
  );
  const tagCommit = execFileSync(
    "git",
    ["-C", ROOT, "rev-parse", `refs/tags/${manifest.tag}^{commit}`],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  ).trim();
  if (tagCommit !== commit)
    throw new Error("Release tag does not point to the scanned source commit.");
  if (
    gh(
      ["release", "view", manifest.tag, "--repo", REPO, "--json", "tagName"],
      true,
    )
  )
    throw new Error(
      "Release already exists. Existing assets and tags will not be replaced.",
    );
  const changelog = (
    await fs.readFile(path.join(ROOT, "CHANGELOG.md"), "utf8")
  ).replace(/\r\n/g, "\n");
  const section = changelog
    .split(`## ${manifest.version}\n`)[1]
    ?.split(/\n## /)[0];
  if (!section) throw new Error("Release version has no CHANGELOG entry.");
  const notesPath = path.join(OUTPUT, "release-notes.md");
  await fs.writeFile(notesPath, notes(manifest, report, results, section));
  gh([
    "release",
    "create",
    manifest.tag,
    artifact.file,
    path.join(OUTPUT, "SHA256SUMS.txt"),
    "--repo",
    REPO,
    "--verify-tag",
    "--draft",
    "--title",
    `KeyForge ${manifest.version} — Windows x64`,
    "--notes-file",
    notesPath,
    ...(manifest.version.includes("-") ? ["--prerelease"] : []),
  ]);
  const uploaded = JSON.parse(
    gh(["release", "view", manifest.tag, "--repo", REPO, "--json", "assets"]),
  );
  const { sha256 } = require("./virustotal.cjs");
  const checksumPath = path.join(OUTPUT, "SHA256SUMS.txt");
  validateAssets(
    uploaded.assets,
    artifact,
    await sha256(checksumPath),
    (await fs.stat(checksumPath)).size,
  );
  gh([
    "release",
    "edit",
    manifest.tag,
    "--repo",
    REPO,
    "--draft=false",
    ...(manifest.version.includes("-") ? [] : ["--latest"]),
  ]);
  console.log(`https://github.com/${REPO}/releases/tag/${manifest.tag}`);
}
module.exports = { validateRelease, validateAssets, notes };
if (require.main === module)
  main().catch(() => {
    console.error(
      "Release publication stopped. Check manifest, completed VirusTotal report, signing state and GitHub permissions.",
    );
    process.exitCode = 1;
  });
