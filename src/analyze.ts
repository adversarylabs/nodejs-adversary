import { readFile, readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { type RuleContext } from "@adversarylabs/sdk";
import { observationFor } from "./rules.js";
import { spec, type MatchExpression, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;

interface SourceFile { path: string; source: string }
interface Detection { rule: RuleSpec; file: string; line: number; snippet: string; label: string; data: Record<string, unknown> }
interface NamedFunction { name: string; body: string }
interface ListenerCall { receiver: string; event: string; callback: string; index: number }

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
  const sources: SourceFile[] = scoped.map((file) => ({ path: file.path, source: file.content }));
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
      const location = locate(file.source, match.trigger);
      if (location === undefined) return [];
      return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
    });
  }

  return matchingSources.flatMap((file) => {
    if (!match.requires.every((pattern) => test(file.source, pattern))) return [];
    const location = locate(file.source, match.pattern);
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
    const removals = findListenerCalls(callback.body, /\b(removeListener|off)\b/);
    const removedEvents = new Set(
      removals
        .filter((call) => call.receiver === first.receiver && call.callback === first.callback)
        .map((call) => call.event),
    );
    const missingEvents = events.filter((event) => !removedEvents.has(event));
    if (missingEvents.length === 0) continue;

    const line = file.source.slice(0, first.index).split(/\r?\n/).length;
    detections.push({
      rule,
      file: file.path,
      line,
      snippet: file.source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "",
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
      if (closeBrace !== undefined) functions.set(name, { name, body: source.slice(openBrace + 1, closeBrace) });
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

function findListenerCalls(source: string, method: RegExp): ListenerCall[] {
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
      calls.push({ receiver, event, callback, index: match.index });
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

function locate(source: string, expression: MatchExpression): { line: number; snippet: string } | undefined {
  const match = new RegExp(expression.pattern, expression.flags).exec(source);
  if (match?.index === undefined) return undefined;
  const line = source.slice(0, match.index).split(/\r?\n/).length;
  return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
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
