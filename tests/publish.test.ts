import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
const { publishBuild } = createRequire(import.meta.url)(
  "../scripts/publish-local-build.cjs",
) as { publishBuild(source: string, destination: string): void };
test("publishing skips identical runtime files but updates changed application files", async () => {
  const directory = await fs.mkdtemp(join(tmpdir(), "keyforge-publish-"));
  try {
    const source = join(directory, "source"),
      destination = join(directory, "build");
    await fs.mkdir(source);
    await fs.mkdir(destination);
    for (const name of ["runtime.dll", "app.asar"]) {
      await fs.writeFile(join(source, name), "current");
      await fs.writeFile(
        join(destination, name),
        name === "runtime.dll" ? "current" : "previous",
      );
      await fs.utimes(join(destination, name), 1000, 1000);
    }
    publishBuild(source, destination);
    assert.equal(
      (await fs.stat(join(destination, "runtime.dll"))).mtimeMs,
      1000000,
    );
    assert.equal(
      await fs.readFile(join(destination, "app.asar"), "utf8"),
      "current",
    );
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
test("publishing refuses nested destination junctions without touching their target", async () => {
  const directory = await fs.mkdtemp(join(tmpdir(), "keyforge-output-link-"));
  try {
    const source = join(directory, "source"),
      destination = join(directory, "build"),
      outside = join(directory, "outside");
    await fs.mkdir(join(source, "resources"), { recursive: true });
    await fs.mkdir(destination);
    await fs.mkdir(outside);
    await fs.writeFile(join(source, "resources", "app.asar"), "new");
    await fs.writeFile(join(outside, "app.asar"), "original");
    await fs.symlink(
      outside,
      join(destination, "resources"),
      process.platform === "win32" ? "junction" : "dir",
    );
    assert.throws(
      () => publishBuild(source, destination),
      /must not be a link/,
    );
    assert.equal(
      await fs.readFile(join(outside, "app.asar"), "utf8"),
      "original",
    );
    await fs.unlink(join(destination, "resources"));
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});
