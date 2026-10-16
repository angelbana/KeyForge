// Pinned Microsoft client utilities; no system installation or token operations.
const fs = require("node:fs/promises");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { execFileSync } = require("node:child_process");

const version = "10.0.0.0p2-Preview";
const expectedHash =
  "23f50f3458c4c5d0b12217c6a5ddfde0137210a30fa870e98b29827f7b43aba5";
const root = path.resolve(__dirname, "..");
const cache = path.resolve(root, "../verification/tools");
const archive = path.join(cache, "OpenSSH-10.0.0.0p2-Win64.zip");
const destination = path.resolve(
  root,
  "../verification/build-work/compiled/openssh",
);
const files = [
  "ssh-keygen.exe",
  "ssh-sk-helper.exe",
  "ssh-pkcs11-helper.exe",
  "libcrypto.dll",
  "LICENSE.txt",
  "NOTICE.txt",
];
const literal = (value) => `'${value.replace(/'/g, "''")}'`;
const powershell = (script) =>
  execFileSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(
        "$ErrorActionPreference = 'Stop'; $env:PSModulePath = Join-Path $PSHOME 'Modules'; " + script,
        "utf16le",
      ).toString("base64"),
    ],
    { windowsHide: true, stdio: "pipe" },
  );

async function prepare() {
  if (process.platform !== "win32") return;
  await fs.mkdir(cache, { recursive: true });
  try {
    await fs.access(archive);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    powershell(
      `Invoke-WebRequest -UseBasicParsing -Uri ${literal(`https://github.com/PowerShell/Win32-OpenSSH/releases/download/${version}/OpenSSH-Win64.zip`)} -OutFile ${literal(archive)} -TimeoutSec 120`,
    );
  }
  const hash = createHash("sha256")
    .update(await fs.readFile(archive))
    .digest("hex");
  if (hash !== expectedHash)
    throw new Error("Microsoft OpenSSH archive SHA256 mismatch");
  const extraction = await fs.mkdtemp(path.join(cache, "openssh-extract-"));
  const resolved = path.resolve(extraction);
  if (
    path.dirname(resolved) !== cache ||
    !path.basename(resolved).startsWith("openssh-extract-")
  )
    throw new Error("Unexpected extraction directory");
  try {
    powershell(
      `Expand-Archive -LiteralPath ${literal(archive)} -DestinationPath ${literal(extraction)}`,
    );
    const source = path.join(extraction, "OpenSSH-Win64");
    const binaries = files.filter((file) => /\.(exe|dll)$/.test(file));
    for (const file of binaries) {
      powershell(
        `$signature = Get-AuthenticodeSignature -LiteralPath ${literal(path.join(source, file))}; if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)') { throw 'Microsoft OpenSSH signature verification failed' }`,
      );
    }
    await fs.mkdir(destination, { recursive: true });
    for (const file of files)
      await fs.copyFile(path.join(source, file), path.join(destination, file));
    await fs.writeFile(
      path.join(destination, "version.json"),
      JSON.stringify({ version, archiveSha256: hash }, null, 2),
    );
    console.log(`Prepared verified Microsoft OpenSSH ${version}`);
  } finally {
    await fs.rm(resolved, { recursive: true, force: true });
  }
}
prepare().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
