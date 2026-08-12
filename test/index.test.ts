import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string, raw = false) => createApp().run({ input: { source: { path: fixture(name) } }, includeRawObservations: raw });
const ruleCases = [
  { key: "shell-exec", id: "nodejs.shell-exec" },
  { key: "dynamic-eval", id: "nodejs.dynamic-eval" },
  { key: "tls-disabled", id: "nodejs.tls-disabled" },
  { key: "path-traversal", id: "nodejs.path-traversal" },
  { key: "weak-random-token", id: "nodejs.weak-random-token" },
  { key: "vm-as-sandbox", id: "nodejs.vm-as-sandbox" },
  { key: "event-listener-cleanup", id: "nodejs.event-listener-cleanup" },
];

test("every initial rule has focused vulnerable and clean coverage", async () => {
  for (const rule of ruleCases) {
    const vulnerable = await review(`rules/${rule.key}/vulnerable`, true);
    assert.equal(vulnerable.findings.some((finding) => finding.ruleId === rule.id), true, `${rule.id} did not detect its vulnerable fixture`);
    assert.equal(vulnerable.rawObservations?.every((item) => item.location?.file !== undefined), true);
    const clean = await review(`rules/${rule.key}/clean`);
    assert.equal(clean.findings.some((finding) => finding.ruleId === rule.id), false, `${rule.id} flagged its clean fixture`);
  }
});

test("accepts a repository without applicable configuration", async () => {
  const output = await review("clean");
  assert.deepEqual(output.findings, []);
  assert.equal(output.assessment?.risk, "none");
  assert.equal(output.opinion?.ship, true);
});

test("an unrelated edit does not surface a legacy direct finding", async () => {
  const legacy = "eval(legacyInput);\n";
  const root = await gitRepository({ "app.js": legacy });
  try {
    await writeFile(join(root, "app.js"), `${legacy}\n// unrelated documentation update\n`);
    const output = await changedReview(root, ["app.js"]);
    assert.equal(output.findings.some((finding) => finding.ruleId === "nodejs.dynamic-eval"), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("matching continues past legacy code to a later changed finding", async () => {
  const legacy = "eval(legacyInput);\n";
  const root = await gitRepository({ "app.js": legacy });
  try {
    await writeFile(join(root, "app.js"), `${legacy}eval(newInput);\n`);
    const output = await changedReview(root, ["app.js"]);
    const observation = output.rawObservations?.find(
      (item) => item.ruleId === "nodejs.dynamic-eval",
    );
    assert.equal(observation?.location?.line, 2);
    assert.equal(observation?.location?.snippet, "eval(newInput);");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a changed semantic line inside a multiline match anchors the finding", async () => {
  const root = await gitRepository({
    "files.ts": [
      'import fs from "node:fs";',
      "fs.readFile(",
      '  path.join(base, "safe.txt"),',
      "  callback,",
      ");",
      "",
    ].join("\n"),
  });
  try {
    await writeFile(
      join(root, "files.ts"),
      [
        'import fs from "node:fs";',
        "fs.readFile(",
        "  path.join(base, req.params.file),",
        "  callback,",
        ");",
        "",
      ].join("\n"),
    );
    const output = await changedReview(root, ["files.ts"]);
    const observation = output.rawObservations?.find(
      (item) => item.ruleId === "nodejs.path-traversal",
    );
    assert.equal(observation?.location?.line, 3);
    assert.equal(observation?.location?.snippet, "path.join(base, req.params.file),");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an unrelated line inside a broad match span is not semantic evidence", async () => {
  const vulnerable = (comment: string) => [
    'import fs from "node:fs";',
    "fs.readFile(",
    comment,
    "  path.join(base, req.params.file),",
    "  callback,",
    ");",
    "",
  ].filter((line) => line !== "").join("\n") + "\n";
  const root = await gitRepository({ "files.ts": vulnerable("  // read the requested file") });
  try {
    await writeFile(join(root, "files.ts"), vulnerable("  // read the requested file safely"));
    const output = await changedReview(root, ["files.ts"]);
    assert.equal(output.findings.some((finding) => finding.ruleId === "nodejs.path-traversal"), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an unrelated edit does not surface legacy listener cleanup", async () => {
  const legacy = [
    "function cleanup() {",
    "  timer.unref();",
    "}",
    "",
    'stream.once("end", cleanup);',
    'stream.once("finish", cleanup);',
    "",
  ].join("\n");
  const root = await gitRepository({ "stream.js": legacy });
  try {
    await writeFile(join(root, "stream.js"), `${legacy}// unrelated documentation update\n`);
    const output = await changedReview(root, ["stream.js"]);
    assert.equal(
      output.findings.some((finding) => finding.ruleId === "nodejs.event-listener-cleanup"),
      false,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a changed event inside a multiline registration anchors listener cleanup", async () => {
  const source = (secondEvent: string) => [
    "function cleanup() {",
    "  timer.unref();",
    "}",
    "",
    "stream.once(",
    '  "end",',
    "  cleanup",
    ");",
    "stream.once(",
    `  "${secondEvent}",`,
    "  cleanup",
    ");",
    "",
  ].join("\n");
  const root = await gitRepository({ "stream.js": source("data") });
  try {
    await writeFile(join(root, "stream.js"), source("finish"));
    const output = await changedReview(root, ["stream.js"]);
    const observation = output.rawObservations?.find(
      (item) => item.ruleId === "nodejs.event-listener-cleanup",
    );
    assert.equal(observation?.location?.line, 10);
    assert.equal(observation?.location?.snippet, '"finish",');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a changed cleanup removal uses unchanged registrations as context", async () => {
  const source = (removedEvent: string) => [
    "function cleanup() {",
    '  stream.removeListener("end", cleanup);',
    `  stream.removeListener("${removedEvent}", cleanup);`,
    "}",
    "",
    'stream.once("end", cleanup);',
    'stream.once("finish", cleanup);',
    "",
  ].join("\n");
  const root = await gitRepository({ "stream.js": source("finish") });
  try {
    await writeFile(join(root, "stream.js"), source("error"));
    const output = await changedReview(root, ["stream.js"]);
    const observation = output.rawObservations?.find(
      (item) => item.ruleId === "nodejs.event-listener-cleanup",
    );
    assert.equal(observation?.location?.line, 3);
    assert.equal(observation?.location?.snippet, 'stream.removeListener("error", cleanup);');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a newly added Node.js file remains fully eligible", async () => {
  const root = await gitRepository({ "README.md": "# service\n" });
  try {
    await writeFile(join(root, "app.js"), "eval(newInput);\n");
    const output = await changedReview(root, ["app.js"]);
    assert.equal(output.findings.some((finding) => finding.ruleId === "nodejs.dynamic-eval"), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("output ordering and protocol envelope are deterministic", async () => {
  const first = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  const second = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  assert.deepEqual(second, first);
  const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(first)));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "lang/nodejs");
});

async function changedReview(root: string, changedFiles: string[]) {
  return createApp().run({
    input: {
      source: { path: root },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
    includeRawObservations: true,
  });
}

async function gitRepository(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "nodejs-adversary-git-"));
  await execute("git", ["init", "--quiet", root]);
  await execute("git", ["-C", root, "config", "user.email", "tests@example.com"]);
  await execute("git", ["-C", root, "config", "user.name", "Tests"]);
  for (const [path, content] of Object.entries(files)) {
    await writeFile(join(root, path), content);
  }
  await execute("git", ["-C", root, "add", "."]);
  await execute("git", ["-C", root, "commit", "--quiet", "-m", "baseline"]);
  return root;
}
