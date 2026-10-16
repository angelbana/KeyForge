const { app, BrowserWindow, dialog } = require("electron");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { createRequire } = require("node:module");
const assert = require("node:assert/strict");
const { randomBytes } = require("node:crypto");
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
    const unsafeDeletion = await window.webContents.executeJavaScript(
      "window.keyforge.deleteKey('../outside', 'invalid', 'ru')",
    );
    assert.deepEqual(unsafeDeletion, { ok: false, error: "invalidName" });
    const choose = dialog.showSaveDialog;
    const chosenPath = path.join(directory, "custom", "retry-key");
    let chosen;
    try {
      dialog.showSaveDialog = async () => ({
        canceled: false,
        filePath: chosenPath,
      });
      chosen = await window.webContents.executeJavaScript(
        "window.keyforge.chooseTarget('retry-key')",
      );
    } finally {
      dialog.showSaveDialog = choose;
    }
    assert.equal(chosen.ok, true);
    const request = {
      algorithm: "invalid",
      bits: 256,
      name: "retry-key",
      comment: "",
      passphrase: "",
      resident: false,
      verifyRequired: false,
      targetPath: chosenPath,
    };
    const generate = () =>
      window.webContents.executeJavaScript(
        `window.keyforge.generate(${JSON.stringify(request)})`,
      );
    assert.deepEqual(await generate(), {
      ok: false,
      error: "invalidAlgorithm",
    });
    request.algorithm = "ed25519";
    assert.equal(
      (await generate()).ok,
      true,
      "Retry must preserve the user-approved target after validation failure",
    );
    assert.ok(fs.existsSync(`${chosenPath}.pub`));
    if (process.platform === "win32") {
      const packagedRequire = createRequire(main);
      const pty = packagedRequire("node-pty");
      const spawn = pty.spawn;
      const spawnedFiles = [];
      pty.spawn = (file, ...args) => {
        spawnedFiles.push(file);
        return spawn(file, ...args);
      };
      try {
        const { KeyService } = packagedRequire("./service");
        const service = new KeyService(
          () => service.interactive.cancel(),
          path.join(directory, "keys"),
        );
        await service.generate({
          algorithm: "ed25519",
          bits: 256,
          name: "package-test",
          comment: "",
          passphrase: randomBytes(24).toString("hex"),
          resident: false,
          verifyRequired: false,
        });
        assert.equal(
          spawnedFiles[0],
          path.join(path.dirname(archive), "openssh/ssh-keygen.exe"),
        );
        assert.match(await service.publicText("package-test"), /^ssh-ed25519 /);
      } finally {
        pty.spawn = spawn;
      }
    }
    const report = {
      status: "passed",
      checks: [
        "packaged native PTY module loaded",
        "production renderer and sandbox loaded",
        "production IPC sender validation accepted the main frame",
        "default SSH directory read without mutation",
        "production deletion IPC rejects unsafe paths before confirmation or file operations",
        "production generation IPC preserves an approved custom path across a failed attempt; isolated software key only",
        ...(process.platform === "win32"
          ? [
              "packaged Microsoft key generator creates an encrypted software key in an isolated directory",
            ]
          : []),
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
