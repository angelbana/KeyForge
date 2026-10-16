// Real Electron + OpenSSH checks, restricted to a new temporary SSH directory.
const { app, BrowserWindow, ipcMain, clipboard, shell } = require("electron");
const fs = require("node:fs/promises");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { randomBytes } = require("node:crypto");
const assert = require("node:assert/strict");
const {
  KeyService,
} = require("../../verification/build-work/compiled/main/service");
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
    stage = "resident overwrite refusal replay (no hardware operation)";
    const pty = require("node-pty");
    const originalSpawn = pty.spawn;
    const writes = [];
    const dataHandlers = [];
    const exitHandlers = [];
    pty.spawn = () => {
      setTimeout(() => {
        for (const handler of dataHandlers)
          handler("Overwrite key in token (y/n)? ");
      }, 0);
      return {
        onData: (handler) => dataHandlers.push(handler),
        onExit: (handler) => exitHandlers.push(handler),
        write: (value) => {
          writes.push(value);
          setTimeout(() => {
            for (const handler of dataHandlers)
              handler("Key enrollment failed: bad permissions\r\n");
            for (const handler of exitHandlers) handler({ exitCode: 255 });
          }, 0);
        },
        kill: () => {
          for (const handler of exitHandlers) handler({ exitCode: 1 });
        },
      };
    };
    try {
      await assert.rejects(
        service.interactive.run(
          "ssh-keygen",
          ["-t", "ed25519-sk"],
          directory,
          "",
        ),
        { message: "hardwareCredentialExists" },
      );
      assert.deepEqual(writes, ["n\r"]);
    } finally {
      pty.spawn = originalSpawn;
    }
    checks.push(
      "replayed token overwrite refusal is preserved as a credential conflict, never confirmed and never overwritten by a later ambiguous bad-permissions error",
    );
    stage = "hardware failure diagnostics without token enrollment";
    const spawnedFiles = [];
    pty.spawn = (file, ...args) => {
      spawnedFiles.push(file);
      return originalSpawn(file, ...args);
    };
    try {
      await assert.rejects(
        service.interactive.run(
          "ssh-keygen",
          [
            "-t",
            "ed25519-sk",
            "-w",
            path.join(directory, "missing-provider.dll"),
            "-f",
            path.join(directory, "unused-hardware-probe"),
          ],
          directory,
          "",
        ),
        (error) =>
          [
            "hardwareProviderUnavailable",
            "hardwareEnrollmentFormatError",
          ].includes(error.message),
      );
    } finally {
      pty.spawn = originalSpawn;
    }
    if (process.platform === "win32")
      assert.equal(
        spawnedFiles[0],
        path.resolve(
          root,
          "../verification/build-work/compiled/openssh/ssh-keygen.exe",
        ),
      );
    checks.push(
      "hardware enrollment failures return safe actionable codes; intentionally missing provider, no physical token used",
    );
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
    let deleteApproval = false,
      deletionPlan;
    const actions = {
      scan: () => service.scan(),
      capabilities: () => service.capabilities(),
      hardwareState: () => service.hardwareState(),
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
      copySnippet: async (server, shell) =>
        clipboard.writeText(service.snippets(server)[shell]),
      validateConfig: (text) => service.validateConfig(text),
      saveConfig: (text, revision) => service.saveConfig(text, revision),
      resolveHost: (alias) => service.resolveHost(alias),
      generate: (request) => service.generate(request),
      cancel: () => service.interactive.cancel(),
      answerPrompt: (id, answer) => service.interactive.answer(id, answer),
      repairPermissions: (name) => service.repairPermissions(name),
      deleteKey: (name, fingerprint) =>
        service.deleteKey(
          name,
          fingerprint,
          async (plan) => {
            deletionPlan = plan;
            return deleteApproval;
          },
          (path) => shell.trashItem(path),
        ),
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
        preload: path.join(
          root,
          "../verification/build-work/compiled/main/preload.js",
        ),
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
      path.join(
        root,
        "../verification/build-work/compiled/renderer/index.html",
      ),
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
    assert.equal(await evaluate("Object.keys(window.keyforge).length"), 21);
    assert.equal(
      await evaluate("document.querySelector('.key-detail .primary').disabled"),
      false,
    );
    await clipboard.clear();
    await evaluate("document.querySelector('.key-detail .primary').click()");
    await new Promise((resolve) => setTimeout(resolve, 1000));
    assert.equal(
      await evaluate(
        "document.querySelector('.key-detail .primary').dataset.copied",
      ),
      "true",
    );
    assert.equal(
      await evaluate("document.querySelectorAll('.alert.success').length"),
      0,
    );
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
    stage = "design themes";
    assert.equal(
      await evaluate("document.documentElement.dataset.theme"),
      "obsidian",
    );
    assert.equal(
      await evaluate("document.querySelectorAll('.key-table tbody tr').length"),
      4,
    );
    assert.equal(
      await evaluate(
        "document.querySelector('.fingerprint-badge').textContent.replace(/\\s/g,'')",
      ),
      (await service.scan()).keys[0].fingerprint,
    );
    for (const [id, background] of [
      ["obsidian", "#0d0e11"],
      ["tokyo", "#1a1b26"],
      ["paper", "#f6f8fa"],
      ["solarized", "#002b36"],
    ]) {
      await evaluate(
        `document.querySelector('.theme-control select').value = '${id}'; document.querySelector('.theme-control select').dispatchEvent(new Event('change', {bubbles:true}))`,
      );
      await new Promise((resolve) => setTimeout(resolve, 300));
      assert.equal(
        await evaluate("document.documentElement.dataset.theme"),
        id,
      );
      assert.equal(
        await evaluate(
          "getComputedStyle(document.documentElement).getPropertyValue('--bg-primary').trim()",
        ),
        background,
      );
      await fs.writeFile(
        path.join(reportDirectory, `theme-${id}.png`),
        (await window.webContents.capturePage()).toPNG(),
      );
    }
    window.webContents.reload();
    await new Promise((resolve) =>
      window.webContents.once("did-finish-load", resolve),
    );
    for (let attempt = 0; attempt < 60; attempt++) {
      if (
        await evaluate(
          "!!document.querySelector('.key-detail .primary') && !document.querySelector('.key-detail .primary').disabled",
        )
      )
        break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.equal(
      await evaluate("document.documentElement.dataset.theme"),
      "solarized",
    );
    await evaluate(
      "document.querySelector('.theme-control select').value = 'obsidian'; document.querySelector('.theme-control select').dispatchEvent(new Event('change', {bubbles:true}))",
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    await evaluate(
      "document.dispatchEvent(new KeyboardEvent('keydown',{key:'k',ctrlKey:true,bubbles:true}))",
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(
      await evaluate("document.activeElement.classList.contains('key-item')"),
      true,
    );
    await evaluate(
      "document.activeElement.dispatchEvent(new KeyboardEvent('keydown',{key:'c',ctrlKey:true,bubbles:true}))",
    );
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(
      await clipboard.readText(),
      await service.publicText("test-ecdsa"),
    );
    await clipboard.clear();
    checks.push(
      "four exact theme palettes, persisted selection after reload, compact key table, paired fingerprint, inline copy and Ctrl+K/C shortcuts",
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
    stage = "strength and hardware indicators";
    assert.equal(
      await evaluate(
        "document.querySelectorAll('.strength-segments > span').length",
      ),
      4,
    );
    assert.equal(
      await evaluate(
        "document.querySelector('[role=meter]').getAttribute('aria-valuenow')",
      ),
      "0",
    );
    await evaluate("document.querySelector('.password-tools button').click()");
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(
      await evaluate(
        "document.querySelector('[role=meter]').getAttribute('aria-valuenow')",
      ),
      "4",
    );
    stage = "passphrase visibility and lifetime";
    await clipboard.clear();
    assert.equal(
      await evaluate("document.querySelector('#generation-passphrase').type"),
      "password",
    );
    await evaluate("document.querySelector('.toggle-passphrase').click()");
    await new Promise((resolve) => setTimeout(resolve, 100));
    stage = "passphrase reveal";
    assert.equal(
      await evaluate("document.querySelector('#generation-passphrase').type"),
      "text",
    );
    assert.equal(
      await evaluate(
        "document.querySelector('#generation-passphrase').value.length === 64",
      ),
      true,
    );
    stage = "passphrase not copied or persisted";
    assert.equal(await clipboard.readText(), "");
    assert.equal(
      await evaluate(
        "Object.values(localStorage).includes(document.querySelector('#generation-passphrase').value)",
      ),
      false,
    );
    stage = "passphrase remasked on blur";
    await evaluate("window.dispatchEvent(new Event('blur'))");
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(
      await evaluate("document.querySelector('#generation-passphrase').type"),
      "password",
    );
    await evaluate("document.querySelector('.toggle-passphrase').click()");
    await new Promise((resolve) => setTimeout(resolve, 100));
    stage = "passphrase remasked on navigation";
    await evaluate("document.querySelectorAll('nav button')[0].click()");
    await new Promise((resolve) => setTimeout(resolve, 100));
    await evaluate("document.querySelectorAll('nav button')[1].click()");
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(
      await evaluate("document.querySelector('#generation-passphrase').type"),
      "password",
    );
    // Clear through a real submission that rejects a duplicate name before key generation.
    stage = "passphrase cleared on submission";
    await evaluate(
      "(() => { const input = document.querySelector('.form-grid input'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'test-ed25519'); input.dispatchEvent(new Event('input', {bubbles:true})); })()",
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    await evaluate("document.querySelector('form').requestSubmit()");
    await new Promise((resolve) => setTimeout(resolve, 500));
    assert.equal(
      await evaluate(
        "document.querySelector('#generation-passphrase').value.length",
      ),
      0,
    );
    assert.equal(
      await evaluate("document.querySelector('#generation-passphrase').type"),
      "password",
    );
    checks.push(
      "generated passphrase can be revealed; remasked on blur/navigation, cleared on submission and never copied or persisted automatically",
    );
    if (process.platform === "win32") {
      const capabilities = await service.capabilities();
      assert.equal(typeof capabilities.windowsElevated, "boolean");
      await evaluate("document.querySelectorAll('.algorithm')[3].click()");
      await new Promise((resolve) => setTimeout(resolve, 100));
      assert.equal(
        await evaluate(
          "document.querySelector('.windows-elevation').dataset.elevated",
        ),
        String(capabilities.windowsElevated),
      );
      checks.push(
        "hardware form shows the actual Windows elevation status from the backend without changing token settings",
      );
    }
    await evaluate("document.querySelectorAll('.algorithm')[3].click()");
    await new Promise((resolve) => setTimeout(resolve, 100));
    await evaluate(
      "document.querySelector('.hardware-options input[type=checkbox]').click()",
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(
      await evaluate(
        "document.querySelector('.resident-application').readOnly && document.querySelector('.resident-application').value === 'ssh:keyforge:' + document.querySelector('.form-grid input').value",
      ),
      true,
    );
    checks.push(
      "resident form displays its filename-specific application without submitting a hardware generation request",
    );
    // Verify event rendering using explicit simulated states; this is not a live token check.
    await evaluate("document.querySelectorAll('nav button')[2].click()");
    await new Promise((resolve) => setTimeout(resolve, 100));
    for (const state of ["ready", "touch", "absent", "unknown"]) {
      window.webContents.send("keyforge:hardwareState", state);
      await new Promise((resolve) => setTimeout(resolve, 100));
      assert.equal(
        await evaluate(
          "document.querySelector('.hardware-state').dataset.state",
        ),
        state,
      );
      if (state === "touch")
        assert.equal(
          await evaluate(
            "getComputedStyle(document.querySelector('.hardware-led')).animationName",
          ),
          await evaluate(
            "matchMedia('(prefers-reduced-motion: reduce)').matches ? 'none' : 'touch-led'",
          ),
        );
    }
    await fs.writeFile(
      path.join(reportDirectory, "hardware-state.png"),
      (await window.webContents.capturePage()).toPNG(),
    );
    checks.push(
      "four-segment passphrase meter; simulated hardware events and reduced-motion-aware touch LED (no physical token verified)",
    );
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
    stage =
      "local deletion UI and real OS Trash (synthetic public-only fixture)";
    const field = (value) => {
      const bytes = Buffer.from(value),
        length = Buffer.alloc(4);
      length.writeUInt32BE(bytes.length);
      return Buffer.concat([length, bytes]);
    };
    const hardwareType = "sk-ssh-ed25519@openssh.com";
    const publicFixture = `${hardwareType} ${Buffer.concat([field(hardwareType), field(randomBytes(32)), field("ssh:trash-test")]).toString("base64")} disposable-fixture`;
    const deletionPath = path.join(directory, "trash-smoke.pub");
    await fs.writeFile(deletionPath, publicFixture);
    await evaluate("document.querySelectorAll('nav button')[0].click()");
    await new Promise((resolve) => setTimeout(resolve, 100));
    await evaluate("document.querySelector('main header button').click()");
    for (let attempt = 0; attempt < 60; attempt++) {
      if (
        await evaluate(
          "document.querySelectorAll('.key-item').length === 5 && !document.querySelector('.delete-key').disabled",
        )
      )
        break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await evaluate(
      "Array.from(document.querySelectorAll('.key-item')).find(button => button.querySelector('strong').textContent === 'trash-smoke').click()",
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.ok(
      await evaluate(
        "document.querySelector('.key-delete').textContent.includes('YubiKey')",
      ),
    );
    await evaluate("document.querySelector('.delete-key').click()");
    for (let attempt = 0; attempt < 60; attempt++) {
      if (await evaluate("!document.querySelector('.delete-key').disabled"))
        break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await fs.access(deletionPath);
    assert.deepEqual(deletionPlan.files, [deletionPath]);
    assert.equal(deletionPlan.hardware, true);
    await evaluate(
      "document.querySelector('.language select').value = 'ru'; document.querySelector('.language select').dispatchEvent(new Event('change', {bubbles:true}));",
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    await evaluate(
      "document.querySelector('.key-delete').scrollIntoView({block:'center'})",
    );
    await fs.writeFile(
      path.join(reportDirectory, "keyforge-delete-ru.png"),
      (await window.webContents.capturePage()).toPNG(),
    );
    deleteApproval = true;
    await evaluate("document.querySelector('.delete-key').click()");
    for (let attempt = 0; attempt < 60; attempt++) {
      if (
        await evaluate(
          "document.querySelectorAll('.key-item').length === 4 && !!document.querySelector('.alert.success')",
        )
      )
        break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await assert.rejects(fs.access(deletionPath), { code: "ENOENT" });
    assert.equal(
      await evaluate("document.querySelectorAll('.key-item').length"),
      4,
    );
    assert.ok(
      await evaluate(
        "document.querySelector('.alert.success').textContent.includes('корзину')",
      ),
    );
    checks.push(
      "delete button, cancellation and list refresh; simulated confirmation, real OS Trash of synthetic public-only fixture; hardware handle warning shown, no user key or token changed",
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
