import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import type { IPty } from "node-pty";
import type { Prompt, HardwareState } from "../shared/types";
import { requestsHardwareTouch, hardwareEnrollmentFailure } from "./hardware";

// No raw terminal output leaves this module. Prompts are classified locally.
export class InteractiveRunner {
  private active: IPty | undefined;
  private cancelled = false;
  private pending:
    { id: string; kind: Prompt["kind"]; terminal: IPty } | undefined;
  constructor(
    private notify: (prompt: Prompt) => void,
    private notifyHardware?: (state: HardwareState) => void,
  ) {}
  answer(id: string, answer: string): void {
    if (
      !this.pending ||
      this.pending.id !== id ||
      typeof answer !== "string" ||
      answer.length > 1024 ||
      /[\r\n\0]/.test(answer)
    )
      throw new Error("invalidPrompt");
    if (this.pending.kind === "hostkey" && answer !== "yes" && answer !== "no")
      throw new Error("invalidPrompt");
    this.pending.terminal.write(`${answer}\r`);
    this.pending = undefined;
  }
  cancel(): void {
    if (this.active) {
      this.cancelled = true;
      this.active.kill();
    }
  }
  run(
    executable: string,
    args: string[],
    cwd: string,
    passphrase?: string,
  ): Promise<void> {
    if (this.active) return Promise.reject(new Error("operationBusy"));
    const pty = require("node-pty") as typeof import("node-pty");
    return new Promise((resolve, reject) => {
      // ConPTY does not apply PATHEXT when looking up an executable.
      let file = executable;
      if (process.platform === "win32") {
        const archive = __dirname.match(/^(.*\.asar)[\\/]/)?.[1];
        const bundled = archive
          ? join(dirname(archive), "openssh")
          : join(__dirname, "../openssh");
        const dirs = [
          ...(executable === "ssh-keygen" ? [bundled] : []),
          join(process.env.SystemRoot || "C:\\Windows", "System32", "OpenSSH"),
          ...(process.env.PATH || "").split(";"),
        ];
        const found = dirs
          .map((dir) => join(dir, `${executable}.exe`))
          .find((candidate) => existsSync(candidate));
        if (!found) {
          reject(new Error("toolUnavailable"));
          return;
        }
        file = found;
      }
      const terminal = pty.spawn(file, args, {
        name: "xterm",
        cols: 120,
        rows: 30,
        cwd,
        env: { ...process.env, LC_ALL: "C", LANG: "C" },
      });
      this.active = terminal;
      this.cancelled = false;
      let buffer = "",
        expired = false;
      const algorithm = args[args.indexOf("-t") + 1];
      const hardwareEnrollment =
        executable === "ssh-keygen" &&
        args.includes("-t") &&
        algorithm?.endsWith("-sk");
      let hardwareFailure: string | undefined;
      const timer = setTimeout(() => {
        expired = true;
        terminal.kill();
      }, 180_000);
      // ssh-keygen disables echo before printing the passphrase prompt.
      terminal.onData((data) => {
        const ansi = new RegExp(
          `${String.fromCharCode(27)}\\[[0-?]*[ -/]*[@-~]`,
          "g",
        );
        buffer = (buffer + data.replace(ansi, "")).slice(-4096);
        if (
          hardwareEnrollment &&
          hardwareFailure !== "hardwareCredentialExists"
        ) {
          hardwareFailure =
            hardwareEnrollmentFailure(buffer) ?? hardwareFailure;
        }
        if (requestsHardwareTouch(buffer)) {
          this.notifyHardware?.("touch");
        }
        if (/overwrite.*\?/i.test(buffer)) {
          terminal.write("n\r");
          buffer = "";
          return;
        }
        if (
          passphrase !== undefined &&
          /(?:enter (?:same |new )?passphrase[^\r\n]*:)/i.test(buffer)
        ) {
          terminal.write(`${passphrase}\r`);
          buffer = "";
          return;
        }
        const kind = /(?:yes\/no|fingerprint).*\?/i.test(buffer)
          ? "hostkey"
          : /(?:enter pin|pin for)[^\r\n]*:/i.test(buffer)
            ? "pin"
            : /(?:password|passphrase)[^\r\n]*:/i.test(buffer)
              ? "password"
              : undefined;
        if (kind && !this.pending) {
          const id = randomUUID();
          const fingerprint = buffer.match(/SHA256:[A-Za-z0-9+/]{20,64}/)?.[0];
          this.pending = { id, kind, terminal };
          buffer = "";
          this.notify({ id, kind, fingerprint });
        }
      });
      terminal.onExit(({ exitCode }) => {
        clearTimeout(timer);
        buffer = "";
        passphrase = undefined;
        this.pending = undefined;
        this.active = undefined;
        if (expired) reject(new Error("operationTimeout"));
        else if (this.cancelled) reject(new Error("operationCancelled"));
        else if (exitCode !== 0)
          reject(
            new Error(
              hardwareFailure ??
                (hardwareEnrollment
                  ? "hardwareEnrollmentFailed"
                  : "operationFailed"),
            ),
          );
        else resolve();
      });
    });
  }
}
