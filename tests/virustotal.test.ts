import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import { join, basename } from "node:path";
import { tmpdir } from "node:os";
const vt = createRequire(import.meta.url)("../scripts/virustotal.cjs");
const counts = {
  harmless: 0,
  malicious: 0,
  suspicious: 0,
  undetected: 5,
  timeout: 1,
  "type-unsupported": 2,
};
const json = (status: number, body: unknown, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers });
async function fixture(action: (file: string, root: string) => Promise<void>) {
  const root = await fs.mkdtemp(join(tmpdir(), "keyforge-vt-"));
  try {
    const file = join(root, "KeyForge-1.2.3-windows-x64.zip");
    await fs.writeFile(file, "public-fixture");
    await action(file, root);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}
function clock() {
  let time = 0;
  return {
    now: () => time,
    pause: async (duration: number) => {
      time += duration;
    },
  };
}
test("VirusTotal submission rejects private paths, links and unknown filenames", async () =>
  fixture(async (file, root) => {
    await assert.rejects(
      vt.publicArtifact(file, [join(root, "different")]),
      /Only a regular final artifact/,
    );
    const privateFile = join(root, "id_ed25519");
    await fs.writeFile(privateFile, "not-a-real-key");
    await assert.rejects(
      vt.publicArtifact(privateFile, [root]),
      /Only named public/,
    );
    await fs.link(file, join(root, "alias"));
    await assert.rejects(
      vt.publicArtifact(file, [root]),
      /Only a regular final artifact/,
    );
  }));
test("VirusTotal refuses upload URLs that could expose the API key", () => {
  for (const value of [
    "http://www.virustotal.com/_ah/upload/id",
    "https://evil.invalid/_ah/upload/id",
    "https://www.virustotal.com.evil.invalid/_ah/upload/id",
    "https://www.virustotal.com:444/_ah/upload/id",
    "https://www.virustotal.com/api/v3/files",
    "not a URL",
  ])
    assert.throws(() => vt.uploadUrl(value));
  assert.equal(
    vt.uploadUrl("https://www.virustotal.com/_ah/upload/id"),
    "https://www.virustotal.com/_ah/upload/id",
  );
});

test("VirusTotal resolves the approved directory as well as the artifact path", async () =>
  fixture(async (file, root) => {
    const parent = await fs.mkdtemp(join(tmpdir(), "keyforge-vt-alias-"));
    const alias = join(parent, "release-root");
    try {
      await fs.symlink(
        root,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
      const artifact = await vt.publicArtifact(join(alias, basename(file)), [
        alias,
      ]);
      assert.equal(artifact.file, await fs.realpath(file));
    } finally {
      await fs.unlink(alias).catch(() => {});
      await fs.rm(parent, { recursive: true, force: true });
    }
  }));

test("VirusTotal refuses an absent key without sending a request", async () =>
  fixture(async (file, root) => {
    const artifact = await vt.publicArtifact(file, [root]);
    let calls = 0;
    const client = vt.createClient({
      key: "",
      ...clock(),
      fetchImpl: async () => {
        calls++;
        throw new Error("Must not send");
      },
    });
    await assert.rejects(
      vt.scan({ artifact, key: "", client, save: async () => {} }),
      /No file was uploaded/,
    );
    assert.equal(calls, 0);
  }));

test("VirusTotal refuses empty and oversized files before hashing or upload", async () =>
  fixture(async (file, root) => {
    await fs.truncate(file, 0);
    await assert.rejects(vt.publicArtifact(file, [root]), /650 MiB/);
    await fs.truncate(file, vt.MAX_FILE + 1);
    await assert.rejects(vt.publicArtifact(file, [root]), /650 MiB/);
  }));

test("VirusTotal waits on an existing pending report without duplicate upload", async () =>
  fixture(async (file, root) => {
    const artifact = await vt.publicArtifact(file, [root]);
    const key = randomBytes(24).toString("hex");
    let calls = 0;
    const client = vt.createClient({
      key,
      ...clock(),
      fetchImpl: async (url: string, options: { method: string }) => {
        calls++;
        assert.equal(options.method, "GET");
        assert.ok(url.endsWith(artifact.sha256));
        return json(200, {
          data: {
            id: artifact.sha256,
            attributes:
              calls === 1
                ? {}
                : {
                    last_analysis_date: 1700000000,
                    last_analysis_stats: counts,
                  },
          },
        });
      },
    });
    const report = await vt.scan({
      artifact,
      key,
      client,
      save: async () => {},
    });
    assert.equal(report.reused, true);
    assert.equal(report.status, "completed");
    assert.equal(calls, 2);
  }));

test("VirusTotal errors never expose the key or upstream response body", async () => {
  const key = randomBytes(24).toString("hex");
  const client = vt.createClient({
    key,
    ...clock(),
    fetchImpl: async () => json(403, { error: key }),
  });
  try {
    await client.request("https://www.virustotal.com/api/v3/files/test");
    assert.fail("Expected rejection");
  } catch (error) {
    assert.ok(error instanceof Error);
    assert.match(error.message, /HTTP 403/);
    assert.ok(!error.message.includes(key));
  }
});
test("VirusTotal reuses an existing completed report without uploading", async () =>
  fixture(async (file, root) => {
    const artifact = await vt.publicArtifact(file, [root]);
    const key = randomBytes(24).toString("hex");
    let calls = 0;
    const saved: Array<Record<string, unknown>> = [];
    const client = vt.createClient({
      key,
      ...clock(),
      fetchImpl: async (
        url: string,
        options: { headers: Record<string, string> },
      ) => {
        calls++;
        assert.ok(options.headers["x-apikey"] === key);
        assert.ok(url.endsWith(artifact.sha256));
        return json(200, {
          data: {
            id: artifact.sha256,
            attributes: {
              sha256: artifact.sha256,
              last_analysis_date: 1700000000,
              last_analysis_stats: counts,
            },
          },
        });
      },
    });
    const report = await vt.scan({
      artifact,
      key,
      client,
      save: async (value: Record<string, unknown>) => {
        saved.push(value);
      },
    });
    assert.equal(calls, 1);
    assert.equal(report.reused, true);
    assert.equal(report.status, "completed");
    assert.equal(report.analysisId, null);
    assert.ok(!JSON.stringify(saved).includes(key));
  }));
test("VirusTotal uploads a small file, saves the analysis ID and waits for completed", async () =>
  fixture(async (file, root) => {
    const artifact = await vt.publicArtifact(file, [root]);
    const key = randomBytes(24).toString("hex");
    const statuses: string[] = [];
    let calls = 0;
    const client = vt.createClient({
      key,
      ...clock(),
      fetchImpl: async (
        url: string,
        options: { method: string; body: FormData },
      ) => {
        calls++;
        if (calls === 1) return json(404, {});
        if (calls === 2) {
          assert.equal(url, "https://www.virustotal.com/api/v3/files");
          assert.equal(options.method, "POST");
          assert.equal(
            (options.body.get("file") as File).name,
            artifact.filename,
          );
          return json(200, { data: { id: "analysis-local-test" } });
        }
        return json(200, {
          data: {
            attributes: {
              status: calls === 3 ? "queued" : "completed",
              date: 1700000000,
              stats: counts,
            },
          },
        });
      },
    });
    const report = await vt.scan({
      artifact,
      key,
      client,
      save: async (value: { status: string; analysisId: string }) => {
        statuses.push(value.status);
        if (value.status === "submitted")
          assert.equal(value.analysisId, "analysis-local-test");
      },
    });
    assert.equal(calls, 4);
    assert.deepEqual(statuses, [
      "checking",
      "submitted",
      "queued",
      "completed",
    ]);
    assert.equal(report.stats.undetected, 5);
    assert.equal(report.stats.timeout, 1);
  }));
test("VirusTotal uses upload_url for files larger than 32 MiB", async () =>
  fixture(async (file, root) => {
    await fs.truncate(file, vt.SMALL_FILE + 1);
    const artifact = await vt.publicArtifact(file, [root]);
    const key = randomBytes(24).toString("hex");
    let calls = 0;
    const client = vt.createClient({
      key,
      ...clock(),
      fetchImpl: async (url: string, options: { body: FormData }) => {
        calls++;
        if (calls === 1) return json(404, {});
        if (calls === 2) {
          assert.ok(url.endsWith("/files/upload_url"));
          return json(200, {
            data: "https://www.virustotal.com/_ah/upload/local-test",
          });
        }
        if (calls === 3) {
          assert.ok(url.endsWith("/_ah/upload/local-test"));
          assert.equal((options.body.get("file") as File).size, artifact.size);
          return json(200, { data: { id: "analysis-large-test" } });
        }
        return json(200, {
          data: {
            attributes: {
              status: "completed",
              date: 1700000000,
              stats: counts,
            },
          },
        });
      },
    });
    assert.equal(
      (await vt.scan({ artifact, key, client, save: async () => {} })).status,
      "completed",
    );
    assert.equal(calls, 4);
  }));
test("VirusTotal renews a single-use large upload URL after 429", async () =>
  fixture(async (file, root) => {
    await fs.truncate(file, vt.SMALL_FILE + 1);
    const artifact = await vt.publicArtifact(file, [root]);
    const key = randomBytes(24).toString("hex");
    const timer = clock();
    let issued = 0;
    const uploads: Array<{ url: string; time: number }> = [];
    const client = vt.createClient({
      key,
      ...timer,
      fetchImpl: async (
        url: string,
        options: { method: string; body: FormData },
      ) => {
        if (url.endsWith(`/files/${artifact.sha256}`)) return json(404, {});
        if (url.endsWith("/files/upload_url"))
          return json(200, {
            data: `https://www.virustotal.com/_ah/upload/attempt-${++issued}`,
          });
        if (options.method === "POST") {
          uploads.push({ url, time: timer.now() });
          if (uploads.length === 1)
            return json(429, {}, { "Retry-After": "60" });
          assert.ok(url.endsWith("/attempt-2"));
          assert.equal((options.body.get("file") as File).size, artifact.size);
          return json(200, { data: { id: "retried-large-analysis" } });
        }
        return json(200, {
          data: {
            attributes: {
              status: "completed",
              date: 1700000000,
              stats: counts,
            },
          },
        });
      },
    });
    assert.equal(
      (await vt.scan({ artifact, key, client, save: async () => {} })).status,
      "completed",
    );
    assert.equal(issued, 2);
    assert.equal(uploads.length, 2);
    assert.notEqual(uploads[0].url, uploads[1].url);
    assert.ok(uploads[1].time - uploads[0].time >= 60000);
    assert.equal(client.requests, 6);
  }));

test("VirusTotal rate limiter spaces requests, honors 429 and stops at its budget", async () => {
  const key = randomBytes(24).toString("hex");
  const timer = clock();
  const starts: number[] = [];
  const client = vt.createClient({
    key,
    ...timer,
    maxRequests: 3,
    fetchImpl: async () => {
      starts.push(timer.now());
      return starts.length === 2
        ? json(429, {}, { "Retry-After": "90" })
        : json(200, {});
    },
  });
  await client.request("https://www.virustotal.com/api/v3/files/test");
  await client.request("https://www.virustotal.com/api/v3/files/test");
  assert.deepEqual(starts, [0, 16000, 106000]);
  await assert.rejects(
    client.request("https://www.virustotal.com/api/v3/files/test"),
    /budget exhausted/,
  );
});
test("VirusTotal never calls a pending analysis completed after a timeout", async () =>
  fixture(async (file, root) => {
    const artifact = await vt.publicArtifact(file, [root]);
    const key = randomBytes(24).toString("hex");
    const states: string[] = [];
    let calls = 0;
    const client = vt.createClient({
      key,
      ...clock(),
      timeoutMs: 70000,
      fetchImpl: async () => {
        calls++;
        if (calls === 1) return json(404, {});
        if (calls === 2) return json(200, { data: { id: "pending-analysis" } });
        return json(200, { data: { attributes: { status: "queued" } } });
      },
    });
    await assert.rejects(
      vt.scan({
        artifact,
        key,
        client,
        save: async (value: { status: string }) => {
          states.push(value.status);
        },
      }),
      /waiting limit/,
    );
    assert.ok(states.includes("submitted"));
    assert.ok(!states.includes("completed"));
  }));
test("VirusTotal preserves detections and rejects mismatched or changed artifacts", async () =>
  fixture(async (file, root) => {
    const artifact = await vt.publicArtifact(file, [root]);
    const key = randomBytes(24).toString("hex");
    const response = {
      data: {
        id: artifact.sha256,
        attributes: {
          last_analysis_date: 1700000000,
          last_analysis_stats: { ...counts, malicious: 1, suspicious: 2 },
        },
      },
    };
    assert.equal(vt.fileResult(response, artifact.sha256).stats.malicious, 1);
    assert.throws(() => vt.fileResult(response, "different"), /does not match/);
    assert.throws(() => vt.stats({ ...counts, malicious: -1 }), /invalid/);
    const client = vt.createClient({
      key,
      ...clock(),
      fetchImpl: async () => {
        await fs.appendFile(file, "changed");
        return json(200, response);
      },
    });
    let last: { status: string } | undefined;
    await assert.rejects(
      vt.scan({
        artifact,
        key,
        client,
        save: async (value: { status: string }) => {
          last = value;
        },
      }),
      /changed during scanning/,
    );
    assert.equal(last?.status, "verification-failed");
  }));
