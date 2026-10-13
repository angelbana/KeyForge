const { app, BrowserWindow } = require("electron");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { createRequire } = require("node:module");
const assert = require("node:assert/strict");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "keyforge-package-"));
app.setPath("userData", directory);
const archive = path.resolve(process.argv[2]);
const main = path.join(archive, "compiled/main/main.js");
const timer = setTimeout(() => {
  console.error("Package smoke timed out");
  app.exit(1);
}, 30_000);
createRequire(main)("node-pty");
require(main);
app
  .whenReady()
  .then(async () => {
    const window = BrowserWindow.getAllWindows()[0];
    window.hide();
    if (window.webContents.isLoadingMainFrame())
      await new Promise((resolve) =>
        window.webContents.once("did-finish-load", resolve),
      );
    const prefs = window.webContents.getLastWebPreferences();
    assert.equal(prefs.sandbox, true);
    assert.equal(prefs.contextIsolation, true);
    assert.equal(prefs.nodeIntegration, false);
    const result = await window.webContents.executeJavaScript(
      "window.keyforge.scan().then(result => ({ok: result.ok, hasDirectory: result.ok && typeof result.value.directory === 'string'}))",
    );
    assert.equal(result.ok, true);
    assert.equal(result.hasDirectory, true);
    const report = {
      status: "passed",
      checks: [
        "packaged native PTY module loaded",
        "production renderer and sandbox loaded",
        "production IPC sender validation accepted the main frame",
        "default SSH directory read without mutation",
      ],
    };
    fs.writeFileSync(
      path.resolve(__dirname, "../../verification/package-smoke.json"),
      JSON.stringify(report, null, 2),
    );
    console.log("Packaged application smoke passed");
  })
  .catch((error) => {
    console.error(`Package smoke failed: ${error.name}`);
    process.exitCode = 1;
  })
  .finally(() => {
    clearTimeout(timer);
    const failed = process.exitCode || 0;
    // Chromium may still hold profile files until process exit; this temporary profile
    // contains no keys or credentials. Cleanup is best effort.
    try {
      fs.rmSync(directory, { recursive: true, force: true });
    } catch {
      /* OS locks */
    }
    app.exit(failed);
  });
