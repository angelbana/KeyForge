const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { URL } = require("node:url");
const { setTimeout: sleep } = require("node:timers/promises");
const { fetch, FormData } = globalThis;
const API = "https://www.virustotal.com/api/v3";
const SMALL_FILE = 32 * 1024 * 1024;
const MAX_FILE = 650 * 1024 * 1024;
const STATUSES = [
  "harmless",
  "malicious",
  "suspicious",
  "undetected",
  "timeout",
  "confirmed-timeout",
  "failure",
  "type-unsupported",
];

class ScanError extends Error {}
async function sha256(file) {
  const hash = createHash("sha256");
  for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}
function inside(root, file) {
  const relative = path.relative(root, file);
  return (
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}
async function publicArtifact(file, roots) {
  const resolved = await fsp.realpath(file);
  const stat = await fsp.lstat(file);
  if (
    stat.isSymbolicLink() ||
    !stat.isFile() ||
    stat.nlink !== 1 ||
    !roots.some((root) => inside(root, resolved))
  )
    throw new ScanError(
      "Only a regular final artifact inside verification/releases or verification/ci-release may be submitted.",
    );
  if (
    !/^KeyForge-[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?-(?:windows-x64|linux-x64|macos-(?:x64|arm64))\.(?:zip|exe|AppImage|dmg|deb)$/.test(
      path.basename(file),
    )
  )
    throw new ScanError(
      "Only named public KeyForge release artifacts may be submitted.",
    );
  if (stat.size <= 0 || stat.size > MAX_FILE)
    throw new ScanError(
      "VirusTotal accepts artifacts between 1 byte and 650 MiB.",
    );
  return {
    file: resolved,
    filename: path.basename(resolved),
    size: stat.size,
    sha256: await sha256(resolved),
  };
}
function uploadUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new ScanError("VirusTotal returned an invalid upload URL.");
  }
  if (
    url.protocol !== "https:" ||
    url.hostname !== "www.virustotal.com" ||
    url.port ||
    url.username ||
    url.password ||
    !url.pathname.startsWith("/_ah/upload/")
  )
    throw new ScanError(
      "Refusing an upload URL outside VirusTotal's HTTPS upload service.",
    );
  return url.href;
}
function stats(value) {
  if (!value || typeof value !== "object")
    throw new ScanError("VirusTotal returned no analysis statistics.");
  const result = {};
  for (const name of STATUSES) {
    const count = value[name] ?? 0;
    if (!Number.isSafeInteger(count) || count < 0)
      throw new ScanError("VirusTotal returned invalid analysis statistics.");
    result[name] = count;
  }
  return result;
}
function fileResult(response, hash) {
  if (
    response?.data?.id !== hash ||
    (response.data.attributes?.sha256 &&
      response.data.attributes.sha256 !== hash)
  )
    throw new ScanError(
      "VirusTotal's file report does not match the artifact SHA256.",
    );
  const attributes = response.data.attributes;
  if (!attributes?.last_analysis_date || !attributes.last_analysis_stats)
    return undefined;
  const result = stats(attributes.last_analysis_stats);
  if (!Object.values(result).some((count) => count > 0)) return undefined;
  return {
    stats: result,
    analysisDate: new Date(attributes.last_analysis_date * 1000).toISOString(),
  };
}
function retryDelay(value, now) {
  if (!value) return 60_000;
  const seconds = Number(value);
  const milliseconds = Number.isFinite(seconds)
    ? seconds * 1000
    : Date.parse(value) - now;
  return Math.max(
    60_000,
    Number.isFinite(milliseconds) ? milliseconds : 60_000,
  );
}
function createClient({
  key,
  fetchImpl = fetch,
  now = Date.now,
  pause = sleep,
  timeoutMs = 30 * 60_000,
  intervalMs = 16_000,
  maxRequests = 500,
}) {
  const deadline = now() + timeoutMs;
  let lastRequest = -Infinity,
    requests = 0;
  async function wait(milliseconds) {
    if (now() + milliseconds >= deadline)
      throw new ScanError(
        "VirusTotal waiting limit reached; analysis is not marked completed.",
      );
    let remaining = milliseconds;
    while (remaining > 0) {
      const step = Math.min(remaining, 30_000);
      await pause(step);
      remaining -= step;
    }
  }
  async function request(
    url,
    { method = "GET", body, allowMissing = false } = {},
  ) {
    for (;;) {
      await wait(Math.max(0, lastRequest + intervalMs - now()));
      if (now() >= deadline)
        throw new ScanError(
          "VirusTotal waiting limit reached; analysis is not marked completed.",
        );
      if (requests >= maxRequests)
        throw new ScanError(
          "VirusTotal request budget exhausted; no further requests sent.",
        );
      lastRequest = now();
      requests++;
      let response;
      try {
        response = await fetchImpl(url, {
          method,
          headers: { "x-apikey": key },
          redirect: "error",
          signal: globalThis.AbortSignal.timeout(
            Math.max(
              1,
              Math.min(method === "POST" ? 600_000 : 60_000, deadline - now()),
            ),
          ),
          ...(body ? { body: await body() } : {}),
        });
      } catch {
        throw new ScanError(
          "VirusTotal network request failed; no credentials or upload URL are logged.",
        );
      }
      if (response.status === 429) {
        const delay = retryDelay(response.headers.get("retry-after"), now());
        await response.body?.cancel();
        await wait(delay);
        continue;
      }
      if (allowMissing && response.status === 404) {
        await response.body?.cancel();
        return undefined;
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw new ScanError(
          `VirusTotal HTTP ${response.status}; analysis is not marked completed.`,
        );
      }
      try {
        return await response.json();
      } catch {
        throw new ScanError("VirusTotal returned an invalid JSON response.");
      }
    }
  }
  return {
    request,
    wait,
    get requests() {
      return requests;
    },
  };
}
async function scan({
  artifact,
  key,
  save,
  notify = () => {},
  client = createClient({ key }),
}) {
  if (!key || !key.trim())
    throw new ScanError("VT_API_KEY is not configured. No file was uploaded.");
  let report = {
    filename: artifact.filename,
    sha256: artifact.sha256,
    size: artifact.size,
    status: "checking",
    reused: false,
    analysisId: null,
    url: `https://www.virustotal.com/gui/file/${artifact.sha256}`,
  };
  const persist = async () => {
    report.requests = client.requests;
    await save({ ...report });
  };
  await persist();
  try {
    let existing = await client.request(`${API}/files/${artifact.sha256}`, {
      allowMissing: true,
    });
    if (existing) {
      report.reused = true;
      report.status = "existing-pending";
      await persist();
      for (;;) {
        const result = fileResult(existing, artifact.sha256);
        if (result) {
          report = { ...report, ...result, status: "completed" };
          break;
        }
        notify("Existing file report is pending; no duplicate upload.");
        await client.wait(30_000);
        existing = await client.request(`${API}/files/${artifact.sha256}`);
      }
    } else {
      let url = `${API}/files`;
      if (artifact.size > SMALL_FILE)
        url = uploadUrl(
          (await client.request(`${API}/files/upload_url`))?.data,
        );
      notify(
        "Uploading final public artifact; submission is not a completed analysis.",
      );
      const uploaded = await client.request(url, {
        method: "POST",
        body: async () => {
          const form = new FormData();
          form.append(
            "file",
            await fs.openAsBlob(artifact.file),
            artifact.filename,
          );
          return form;
        },
      });
      const id = uploaded?.data?.id;
      if (typeof id !== "string" || !/^[A-Za-z0-9_+=/-]{1,512}$/.test(id))
        throw new ScanError("VirusTotal returned no valid analysis ID.");
      report.analysisId = id;
      report.status = "submitted";
      report.submittedAt = new Date().toISOString();
      await persist();
      for (;;) {
        await client.wait(30_000);
        const analysis = await client.request(
          `${API}/analyses/${encodeURIComponent(id)}`,
        );
        const status = analysis?.data?.attributes?.status;
        if (
          analysis?.meta?.file_info?.sha256 &&
          analysis.meta.file_info.sha256 !== artifact.sha256
        )
          throw new ScanError(
            "VirusTotal's analysis does not match the artifact SHA256.",
          );
        if (status === "completed") {
          report.stats = stats(analysis.data.attributes.stats);
          report.analysisDate = new Date(
            analysis.data.attributes.date * 1000,
          ).toISOString();
          report.status = "completed";
          break;
        }
        if (status !== "queued" && status !== "in-progress")
          throw new ScanError(
            "VirusTotal returned an unknown analysis status.",
          );
        report.status = status;
        await persist();
        notify(`VirusTotal analysis ${status}; waiting for completed.`);
      }
    }
    if ((await sha256(artifact.file)) !== artifact.sha256)
      throw new ScanError(
        "The final artifact changed during scanning; do not publish it.",
      );
    report.verifiedAt = new Date().toISOString();
    await persist();
    return report;
  } catch (error) {
    report.error =
      error instanceof ScanError
        ? error.message
        : "VirusTotal scan could not finish.";
    if (report.status === "completed") report.status = "verification-failed";
    await persist();
    throw error;
  }
}
async function main() {
  const [file, ...extra] = process.argv.slice(2);
  if (!file || extra.length)
    throw new ScanError(
      "Usage: node scripts/virustotal.cjs <final-public-KeyForge-artifact>",
    );
  const key = process.env.VT_API_KEY;
  if (!key || !key.trim())
    throw new ScanError("VT_API_KEY is not configured. No file was uploaded.");
  const root = path.resolve(__dirname, "..");
  const artifact = await publicArtifact(file, [
    path.resolve(root, "../verification/releases"),
    path.resolve(root, "../verification/ci-release"),
  ]);
  const output = path.join(
    path.dirname(artifact.file),
    `${artifact.filename}.virustotal.json`,
  );
  const report = await scan({
    artifact,
    key,
    save: (value) =>
      fsp.writeFile(output, JSON.stringify(value, null, 2) + "\n", {
        mode: 0o600,
      }),
    notify: (value) => console.log(value),
  });
  console.log(
    `VirusTotal analysis completed. Malicious: ${report.stats.malicious}; suspicious: ${report.stats.suspicious}. ${report.url}`,
  );
  if (report.stats.malicious || report.stats.suspicious)
    throw new ScanError(
      "VirusTotal returned detections. Review the report before publication.",
    );
}
module.exports = {
  ScanError,
  SMALL_FILE,
  MAX_FILE,
  sha256,
  publicArtifact,
  uploadUrl,
  stats,
  fileResult,
  retryDelay,
  createClient,
  scan,
};
if (require.main === module)
  main().catch((error) => {
    console.error(
      error instanceof ScanError
        ? error.message
        : "Release scan failed. No credentials are logged.",
    );
    process.exitCode = 1;
  });
