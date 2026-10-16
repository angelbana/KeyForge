const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
function publishBuild(source, destination) {
  if (!fs.existsSync(source))
    throw new Error("Unpacked application was not built");
  fs.mkdirSync(destination, { recursive: true });
  if (fs.lstatSync(destination).isSymbolicLink())
    throw new Error("Build destination must not be a link");
  const hash = (file) =>
    createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  const inside = (root, file) => {
    const relative = path.relative(root, file);
    return (
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative)
    );
  };
  for (const name of fs.readdirSync(source))
    fs.cpSync(path.join(source, name), path.join(destination, name), {
      recursive: true,
      force: true,
      verbatimSymlinks: true,
      filter: (from, to) => {
        const input = fs.lstatSync(from);
        let output;
        try {
          output = fs.lstatSync(to);
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
        if (input.isSymbolicLink()) {
          const link = fs.readlinkSync(from);
          if (
            path.isAbsolute(link) ||
            !inside(source, path.resolve(path.dirname(from), link))
          )
            throw new Error("Application source link escapes the package");
          if (output?.isSymbolicLink() && fs.readlinkSync(to) === link)
            return false;
        }
        if (output?.isSymbolicLink())
          throw new Error("Application output must not be a link");
        // Unchanged Electron DLLs may be locked by a running application on Windows.
        return !(
          input.isFile() &&
          output?.isFile() &&
          input.size === output.size &&
          hash(from) === hash(to)
        );
      },
    });
}
module.exports = { publishBuild };
if (require.main === module) {
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
  publishBuild(source, destination);
  console.log("Current unpacked application is available in build/");
}
