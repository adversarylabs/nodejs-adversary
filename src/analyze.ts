import { execFile } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import { type RuleContext } from "@adversarylabs/sdk";
import { observationFor } from "./rules.js";
import { spec, type MatchExpression, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
const execute = promisify(execFile);

interface SourceFile {
  path: string;
  source: string;
  changedLines: Set<number>;
  status: "added" | "modified" | "repository";
}
interface Detection { rule: RuleSpec; file: string; line: number; snippet: string; label: string; data: Record<string, unknown> }
interface NamedFunction { name: string; body: string; bodyStart: number }
interface ListenerCall { receiver: string; event: string; callback: string; index: number; end: number }

const LIFECYCLE_EVENTS = new Set(["abort", "close", "disconnect", "end", "error", "exit", "finish", "timeout"]);

export async function analyzeRepository(ctx: RuleContext): Promise<void> {
  // Full tree for existence/context checks; content uses CLI/SDK review scope.
  const allPaths = await walk(ctx.repoPath);
  const scoped = await ctx.loadInScopeSources({
    include: (path) =>
      !path.split("/").some((segment) => SKIPPED.has(segment)) &&
      spec.files.some((glob) => matchesGlob(path, glob)),
    limit: MAX_FILES,
  });
  const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
  const sources: SourceFile[] = [];
  for (const file of scoped) {
    const change = wholeTarget || file.status === "repository"
      ? { changedLines: new Set<number>(), status: "repository" as const }
      : await changedSource(ctx, file.path);
    sources.push({
      path: file.path,
      source: file.content,
      changedLines: change.changedLines,
      status: change.status,
    });
  }
  ctx.summary.files_scanned = sources.length;

  const detections = spec.rules.flatMap((rule) => evaluate(rule, sources, allPaths));
  detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
  for (const detection of detections) ctx.observe(observationFor(detection));

  if (sources.length > 0 && detections.length === 0) {
    ctx.review.positive({
      key: `${spec.id}.reviewed`,
      summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
      evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
    });
  }
}

function evaluate(rule: RuleSpec, sources: SourceFile[], allPaths: string[]): Detection[] {
  const match = rule.match;
  if (match.kind === "event-listener-cleanup") {
    return sources
      .filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)))
      .flatMap((file) => findIncompleteListenerCleanup(rule, file));
  }

  if (match.kind === "missing-file") {
    const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
    const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
    if (triggers.length === 0 || required) return [];
    return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
  }

  const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
  if (match.kind === "missing-content") {
    return matchingSources.flatMap((file) => {
      if (!test(file.source, match.trigger) || test(file.source, match.required)) return [];
      const location = locateEligible(file, match.trigger);
      if (location === undefined) return [];
      return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
    });
  }

  return matchingSources.flatMap((file) => {
    if (!match.requires.every((pattern) => test(file.source, pattern))) return [];
    const location = locateEligible(file, match.pattern, match.anchors);
    if (location === undefined) return [];
    return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
  });
}

function findIncompleteListenerCleanup(rule: RuleSpec, file: SourceFile): Detection[] {
  const functions = findNamedFunctions(file.source);
  const registrations = findListenerCalls(file.source, /\b(once|on|addListener)\b/);
  const groups = new Map<string, ListenerCall[]>();

  for (const registration of registrations) {
    const key = `${registration.receiver}\0${registration.callback}`;
    groups.set(key, [...(groups.get(key) ?? []), registration]);
  }

  const detections: Detection[] = [];
  for (const calls of groups.values()) {
    const first = calls[0];
    if (first === undefined) continue;
    const events = [...new Set(calls.map((call) => call.event))];
    if (events.length < 2 || events.some((event) => !LIFECYCLE_EVENTS.has(event))) continue;

    const callback = functions.get(first.callback);
    if (callback === undefined || !isTeardownCallback(callback)) continue;
    const removals = findListenerCalls(callback.body, /\b(removeListener|off)\b/, callback.bodyStart);
    const removedEvents = new Set(
      removals
        .filter((call) => call.receiver === first.receiver && call.callback === first.callback)
        .map((call) => call.event),
    );
    const missingEvents = events.filter((event) => !removedEvents.has(event));
    if (missingEvents.length === 0) continue;

    const relevantRemovals = removals.filter(
      (call) => call.receiver === first.receiver && call.callback === first.callback,
    );
    const line = eligibleRangesAnchor(file, [...calls, ...relevantRemovals]);
    if (line === undefined) continue;
    detections.push({
      rule,
      file: file.path,
      line,
      snippet: snippetAt(file.source, line),
      label: `${first.callback} remains registered for ${missingEvents.join(", ")}`,
      data: {
        receiver: first.receiver,
        callback: first.callback,
        lifecycleEvents: events,
        missingRemovals: missingEvents,
      },
    });
  }

  return detections;
}

function findNamedFunctions(source: string): Map<string, NamedFunction> {
  const functions = new Map<string, NamedFunction>();
  const definitions = [
    /\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/g,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function(?:\s+[A-Za-z_$][\w$]*)?\s*\([^)]*\)\s*\{/g,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{/g,
  ];

  for (const definition of definitions) {
    for (const match of source.matchAll(definition)) {
      const name = match[1];
      if (name === undefined || match.index === undefined || functions.has(name)) continue;
      const openBrace = source.indexOf("{", match.index + match[0].length - 1);
      const closeBrace = findClosingBrace(source, openBrace);
      if (closeBrace !== undefined) functions.set(name, { name, body: source.slice(openBrace + 1, closeBrace), bodyStart: openBrace + 1 });
    }
  }

  return functions;
}

function findClosingBrace(source: string, openBrace: number): number | undefined {
  if (openBrace < 0) return undefined;
  let depth = 0;
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;

  for (let index = openBrace; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (lineComment) {
      if (character === "\n") lineComment = false;
      continue;
    }
    if (blockComment) {
      if (character === "*" && next === "/") { blockComment = false; index += 1; }
      continue;
    }
    if (quote !== undefined) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = undefined;
      continue;
    }
    if (character === "/" && next === "/") { lineComment = true; index += 1; continue; }
    if (character === "/" && next === "*") { blockComment = true; index += 1; continue; }
    if (character === "'" || character === '"' || character === "`") { quote = character; continue; }
    if (character === "{") depth += 1;
    else if (character === "}" && --depth === 0) return index;
  }
  return undefined;
}

function findListenerCalls(source: string, method: RegExp, offset = 0): ListenerCall[] {
  const methodPattern = method.source;
  const expression = new RegExp(
    `([A-Za-z_$][\\w$]*(?:(?:\\.[A-Za-z_$][\\w$]*)|(?:\\[[^\\]\\r\\n]+\\]))*)\\s*\\.\\s*${methodPattern}\\s*\\(\\s*(['"])([^'"\\r\\n]+)\\3\\s*,\\s*([A-Za-z_$][\\w$]*)\\b`,
    "g",
  );
  const calls: ListenerCall[] = [];
  for (const match of source.matchAll(expression)) {
    const receiver = match[1]?.replace(/\s+/g, "");
    const event = match[4];
    const callback = match[5];
    if (receiver !== undefined && event !== undefined && callback !== undefined && match.index !== undefined) {
      calls.push({ receiver, event, callback, index: offset + match.index, end: offset + match.index + match[0].length });
    }
  }
  return calls;
}

function isTeardownCallback(callback: NamedFunction): boolean {
  return /cleanup|teardown|dispose|release|finalize|settle/i.test(callback.name) ||
    /\.(?:removeListener|off|destroy|close|abort|dispose|unref)\s*\(|\[\s*kUnref\s*\]\s*\(|\bclear(?:Timeout|Interval)\s*\(/.test(callback.body);
}

function test(source: string, expression: MatchExpression): boolean {
  return new RegExp(expression.pattern, expression.flags).test(source);
}

function locateEligible(
  file: SourceFile,
  expression: MatchExpression,
  anchors?: readonly MatchExpression[],
): { line: number; snippet: string } | undefined {
  const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
  for (const match of file.source.matchAll(new RegExp(expression.pattern, flags))) {
    if (match.index === undefined || match[0] === "") continue;
    const line = file.status === "modified" && anchors !== undefined
      ? eligibleExpressionAnchor(file, match.index, match[0], anchors)
      : eligibleRangeAnchor(file, match.index, match.index + match[0].length);
    if (line !== undefined) return { line, snippet: snippetAt(file.source, line) };
  }
  return undefined;
}

function eligibleExpressionAnchor(
  file: SourceFile,
  offset: number,
  matchedSource: string,
  anchors: readonly MatchExpression[],
): number | undefined {
  let eligible: number | undefined;
  for (const anchor of anchors) {
    const flags = anchor.flags.includes("g") ? anchor.flags : `${anchor.flags}g`;
    for (const match of matchedSource.matchAll(new RegExp(anchor.pattern, flags))) {
      if (match.index === undefined || match[0] === "") continue;
      const line = eligibleRangeAnchor(
        file,
        offset + match.index,
        offset + match.index + match[0].length,
      );
      if (line !== undefined && (eligible === undefined || line < eligible)) eligible = line;
    }
  }
  return eligible;
}

function eligibleRangesAnchor(
  file: SourceFile,
  ranges: readonly Pick<ListenerCall, "index" | "end">[],
): number | undefined {
  if (file.status !== "modified") {
    const first = ranges.reduce<Pick<ListenerCall, "index" | "end"> | undefined>(
      (earliest, range) => earliest === undefined || range.index < earliest.index ? range : earliest,
      undefined,
    );
    return first === undefined ? undefined : lineAt(file.source, first.index);
  }

  let anchor: number | undefined;
  for (const range of ranges) {
    const candidate = eligibleRangeAnchor(file, range.index, range.end);
    if (candidate !== undefined && (anchor === undefined || candidate < anchor)) anchor = candidate;
  }
  return anchor;
}

function eligibleRangeAnchor(file: SourceFile, start: number, end: number): number | undefined {
  const startLine = lineAt(file.source, start);
  if (file.status !== "modified") return startLine;
  const endLine = lineAt(file.source, Math.max(start, end - 1));
  for (let line = startLine; line <= endLine; line += 1) {
    if (file.changedLines.has(line)) return line;
  }
  return undefined;
}

function lineAt(source: string, index: number): number {
  return source.slice(0, index).split(/\r?\n/).length;
}

function snippetAt(source: string, line: number): string {
  return source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "";
}

async function changedSource(
  ctx: RuleContext,
  path: string,
): Promise<Pick<SourceFile, "changedLines" | "status">> {
  const base = ctx.change?.baseRef;
  if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
    return { changedLines: new Set<number>(), status: "added" };
  }

  const args = ["diff", "--unified=0", base];
  const head = ctx.change?.headRef;
  if (head !== undefined && !ctx.change?.worktree) args.push(head);
  args.push("--", path);
  const patch = await gitOutput(ctx.repoPath, args);
  return { changedLines: changedLineNumbers(patch), status: "modified" };
}

async function existsAtRevision(repoPath: string, revision: string, path: string): Promise<boolean> {
  try {
    await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

async function gitOutput(repoPath: string, args: string[]): Promise<string> {
  const result = await execute("git", ["-C", repoPath, ...args], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  return result.stdout;
}

function changedLineNumbers(patch: string): Set<number> {
  const lines = new Set<number>();
  for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    const start = Number(match[1]);
    const count = match[2] === undefined ? 1 : Number(match[2]);
    for (let line = start; line < start + count; line += 1) lines.add(line);
  }
  return lines;
}

async function walk(root: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(relative: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    const entries = await readdir(join(root, relative), { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const path = relative ? join(relative, entry.name) : entry.name;
      if (entry.isDirectory() && !SKIPPED.has(entry.name)) await visit(path);
      else if (entry.isFile()) files.push(path.split(sep).join("/"));
    }
  }
  await visit("");
  return files.sort();
}

function matchesGlob(path: string, glob: string): boolean {
  let pattern = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") { pattern += "(?:.*/)?"; index += 2; }
      else { pattern += ".*"; index += 1; }
    } else if (character === "*") pattern += "[^/]*";
    else if (character === "?") pattern += "[^/]";
    else pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
  }
  return new RegExp(`${pattern}$`, "i").test(path);
}
