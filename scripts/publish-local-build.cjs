const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const packages = path.resolve(root, "../verification/build-work/packages");
const platform =
  process.platform === "win32"
    ? "win"
    : process.platform === "darwin"
      ? "mac"
      : "linux";
const folder =
  platform === "mac"
    ? `mac${process.arch === "arm64" ? "-arm64" : ""}`
    : `${platform}${process.arch === "x64" ? "" : `-${process.arch}`}-unpacked`;
const source = path.join(packages, folder);
const destination = path.resolve(root, "../build");
if (!fs.existsSync(source))
  throw new Error("Unpacked application was not built");
fs.mkdirSync(destination, { recursive: true });
if (fs.lstatSync(destination).isSymbolicLink())
  throw new Error("Build destination must not be a link");
// Only copy application files; compilation, caches and packaging reports stay outside build/.
for (const name of fs.readdirSync(source)) {
  const target = path.join(destination, name);
  if (fs.existsSync(target) && fs.lstatSync(target).isSymbolicLink())
    throw new Error("Application output must not be a link");
  fs.cpSync(path.join(source, name), target, { recursive: true, force: true });
}
console.log("Current unpacked application is available in build/");
