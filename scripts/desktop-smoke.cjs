// Real Electron + OpenSSH checks, restricted to a new temporary SSH directory.
const { app, BrowserWindow, ipcMain, clipboard } = require("electron");
const fs = require("node:fs/promises");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { randomBytes } = require("node:crypto");
const assert = require("node:assert/strict");
const { KeyService } = require("../../build/compiled/main/service");
let service, directory, window;
let stage = "startup",
  failed = false;
const root = path.resolve(__dirname, "..");
const reportDirectory = path.resolve(root, "../verification");
const checks = [];
const timeout = setTimeout(() => {
  service?.interactive.cancel();
  console.error("Desktop smoke timed out");
  app.exit(1);
}, 90_000);
app
  .whenReady()
  .then(async () => {
    directory = await fs.mkdtemp(path.join(tmpdir(), "keyforge-electron-"));
    app.setPath("userData", path.join(directory, "profile"));
    service = new KeyService(() => service.interactive.cancel(), directory);
    let passphrase = randomBytes(32).toString("hex");
    for (const [algorithm, bits] of [
      ["ed25519", 256],
      ["ecdsa", 384],
      ["rsa", 3072],
    ]) {
      stage = `${algorithm} generation`;
      await service.generate({
        algorithm,
        bits,
        name: `test-${algorithm}`,
        comment: "isolated smoke check",
        passphrase,
        resident: false,
        verifyRequired: false,
      });
      const result = await service.scan();
      assert.equal(
        result.keys.find((key) => key.name === `test-${algorithm}`).encrypted,
        true,
      );
      stage = `${algorithm} decryption`;
      await service.interactive.run(
        "ssh-keygen",
        ["-y", "-f", path.join(directory, `test-${algorithm}`)],
        directory,
        passphrase,
      );
      checks.push(
        `${algorithm}: encrypted key created and decrypted by OpenSSH`,
      );
    }
    // Drop the reference as soon as the encryption/decryption checks finish.
    // eslint-disable-next-line no-useless-assignment
    passphrase = "";
    stage = "empty passphrase";
    await service.generate({
      algorithm: "ed25519",
      bits: 256,
      name: "test-empty",
      comment: "",
      passphrase: "",
      resident: false,
      verifyRequired: false,
    });
    assert.equal(
      (await service.scan()).keys.find((key) => key.name === "test-empty")
        .encrypted,
      false,
    );
    await assert.rejects(
      service.generate({
        algorithm: "ed25519",
        bits: 256,
        name: "test-empty",
        comment: "",
        passphrase: "",
        resident: false,
        verifyRequired: false,
      }),
      /keyExists/,
    );
    checks.push("empty passphrase and overwrite prevention");
    stage = "interactive cancellation";
    await assert.rejects(
      service.interactive.run(
        "ssh-keygen",
        ["-t", "ed25519", "-f", path.join(directory, "cancelled")],
        directory,
      ),
      /operationCancelled/,
    );
    checks.push("interactive prompt cancellation");
    const actions = {
      scan: () => service.scan(),
      capabilities: () => service.capabilities(),
      config: () => service.config(),
      copyPublic: async (name) =>
        clipboard.writeText(await service.publicText(name)),
      serverCommand: (name, user) => service.serverCommand(name, user),
      copyServerCommand: async (name, user) => {
        const command = await service.serverCommand(name, user);
        await clipboard.writeText(command);
        return command;
      },
      snippets: (server) => service.snippets(server),
      validateConfig: (text) => service.validateConfig(text),
      saveConfig: (text, revision) => service.saveConfig(text, revision),
      resolveHost: (alias) => service.resolveHost(alias),
      generate: (request) => service.generate(request),
      cancel: () => service.interactive.cancel(),
      answerPrompt: (id, answer) => service.interactive.answer(id, answer),
      repairPermissions: (name) => service.repairPermissions(name),
      chooseTarget: () => null,
    };
    for (const [name, action] of Object.entries(actions))
      ipcMain.handle(`keyforge:${name}`, async (_event, ...args) => {
        try {
          return { ok: true, value: await action(...args) };
        } catch {
          return { ok: false, error: "operationFailed" };
        }
      });
    window = new BrowserWindow({
      width: 1240,
      height: 860,
      show: false,
      webPreferences: {
        preload: path.join(root, "../build/compiled/main/preload.js"),
        sandbox: true,
        contextIsolation: true,
        nodeIntegration: false,
        backgroundThrottling: false,
        offscreen: true,
      },
    });
    stage = "renderer startup";
    let errors = 0;
    window.webContents.on("console-message", (_event, _level, message) => {
      if (message.includes("Uncaught")) errors++;
    });
    await window.loadFile(
      path.join(root, "../build/compiled/renderer/index.html"),
    );
    const evaluate = (code) => window.webContents.executeJavaScript(code);
    for (let attempt = 0; attempt < 60; attempt++) {
      if (
        await evaluate(
          "document.querySelectorAll('.key-item').length === 4 && !document.querySelector('.key-detail .primary').disabled",
        )
      )
        break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(
      await evaluate("document.querySelectorAll('.key-item').length"),
      4,
    );
    stage = "preload and clipboard";
    assert.equal(await evaluate("typeof window.require"), "undefined");
    assert.equal(await evaluate("Object.keys(window.keyforge).length"), 17);
    assert.equal(
      await evaluate("document.querySelector('.key-detail .primary').disabled"),
      false,
    );
    await clipboard.clear();
    await evaluate("document.querySelector('.key-detail .primary').click()");
    await new Promise((resolve) => setTimeout(resolve, 1000));
    assert.match(await clipboard.readText(), /^(ssh-|ecdsa-|sk-)/);
    await clipboard.clear();
    await fs.mkdir(reportDirectory, { recursive: true });
    stage = "server command clipboard";
    await evaluate(
      "document.querySelector('.key-detail button[aria-expanded]').click()",
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    await evaluate("document.querySelector('.prepare-server-command').click()");
    for (let attempt = 0; attempt < 30; attempt++) {
      if (
        await evaluate(
          "!!document.querySelector('.copy-server-command') && !document.querySelector('.copy-server-command').disabled",
        )
      )
        break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await evaluate("document.querySelector('.copy-server-command').click()");
    await new Promise((resolve) => setTimeout(resolve, 500));
    assert.equal(
      await clipboard.readText(),
      await service.serverCommand("test-ecdsa", ""),
    );
    await clipboard.clear();
    checks.push(
      "server-side command prepared and copied through the real UI and clipboard",
    );
    await fs.writeFile(
      path.join(reportDirectory, "keyforge-ru.png"),
      (await window.webContents.capturePage()).toPNG(),
    );
    stage = "language and navigation";
    await evaluate(
      "document.querySelector('.language select').value = 'en'; document.querySelector('.language select').dispatchEvent(new Event('change', {bubbles:true}))",
    );
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(await evaluate("document.documentElement.lang"), "en");
    for (let index = 0; index < 4; index++) {
      await evaluate(
        `document.querySelectorAll('nav button')[${index}].click()`,
      );
      await new Promise((resolve) => setTimeout(resolve, 100));
      assert.ok(
        await evaluate(
          "document.querySelector('main h1').textContent.length > 0",
        ),
      );
      assert.equal(
        await evaluate("document.querySelectorAll('.fallback').length"),
        0,
      );
    }
    await evaluate("document.querySelectorAll('nav button')[1].click()");
    await new Promise((resolve) => setTimeout(resolve, 100));
    await fs.writeFile(
      path.join(reportDirectory, "keyforge-en.png"),
      (await window.webContents.capturePage()).toPNG(),
    );
    assert.equal(errors, 0);
    checks.push(
      "sandboxed preload; key explorer; public clipboard; both languages; all four tabs",
    );
    await fs.writeFile(
      path.join(reportDirectory, "desktop-smoke.json"),
      JSON.stringify(
        { status: "passed", electron: process.versions.electron, checks },
        null,
        2,
      ),
    );
    console.log(
      JSON.stringify({
        status: "passed",
        checks: checks.length,
        electron: process.versions.electron,
      }),
    );
  })
  .catch((error) => {
    console.error(
      `Desktop smoke failed at ${stage}: ${error.name}${error instanceof TypeError ? ": " + error.message : ""}`,
    );
    failed = true;
  })
  .finally(async () => {
    clearTimeout(timeout);
    service?.interactive.cancel();
    window?.destroy();
    if (directory) await fs.rm(directory, { recursive: true, force: true });
    app.exit(failed ? 1 : 0);
  });
