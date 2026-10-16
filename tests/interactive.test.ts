import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { randomInt } from "node:crypto";
import { InteractiveRunner } from "../src/main/interactive";
import type { Prompt } from "../src/shared/types";
import type { IPty } from "node-pty";

test("fragmented terminal escapes do not hide PIN prompts or permit control answers", async () => {
  const pty = createRequire(import.meta.url)(
    "node-pty",
  ) as typeof import("node-pty");
  let data!: (text: string) => void;
  let exit!: (event: { exitCode: number }) => void;
  const writes: string[] = [];
  const prompts: Prompt[] = [];
  const spawnMock = mock.method(
    pty,
    "spawn",
    () =>
      ({
        onData: (handler: typeof data) => {
          data = handler;
        },
        onExit: (handler: typeof exit) => {
          exit = handler;
        },
        write: (value: string) => {
          writes.push(value);
        },
        kill: () => exit({ exitCode: 1 }),
      }) as unknown as IPty,
  );
  const runner = new InteractiveRunner((prompt) => prompts.push(prompt));
  const result = runner.run("ssh-keygen", ["-t", "ed25519-sk"], process.cwd());
  // Attach the rejection handler before assertions, so failed assertions can clean up.
  const completed = assert.rejects(result, /operationCancelled/);
  try {
    data("Enter P\x1b[");
    data("0mIN for authenticator: ");
    assert.equal(prompts.length, 1);
    assert.equal(prompts[0].kind, "pin");
    for (const answer of ["a\x03b", "a\x04b", "a\x1bb", "a\t b"])
      assert.throws(
        () => runner.answer(prompts[0].id, answer),
        /invalidPrompt/,
      );
    assert.equal(writes.length, 0);
    runner.answer(prompts[0].id, String(randomInt(100000, 999999)));
    assert.equal(writes.length, 1);
  } finally {
    runner.cancel();
    await completed;
    spawnMock.mock.restore();
  }
});
