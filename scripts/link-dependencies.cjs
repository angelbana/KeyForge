const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const target = path.join(root, "node_modules");
const link = path.resolve(
  root,
  "../verification/build-work/compiled/node_modules",
);
fs.cpSync(
  path.join(root, "assets"),
  path.resolve(root, "../verification/build-work/compiled/assets"),
  { recursive: true },
);
try {
  const existing = fs.lstatSync(link);
  if (
    !existing.isSymbolicLink() ||
    fs.realpathSync(link) !== fs.realpathSync(target)
  )
    throw new Error("Unexpected dependency link");
} catch (error) {
  if (error.code !== "ENOENT") throw error;
  fs.symlinkSync(
    target,
    link,
    process.platform === "win32" ? "junction" : "dir",
  );
}
