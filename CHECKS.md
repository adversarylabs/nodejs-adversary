# Checks — what nodejs detects

This file is the **public audit list** of detectors for the **nodejs** adversary. High-confidence server-side JavaScript/Node security defects with file:line evidence. Framework-specialized concerns (React components, Next.js config) and package-manager supply chain are owned elsewhere — this adversary covers the Node runtime security surface.

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** `*.js`, `*.mjs`, `*.cjs`, `*.ts` server-side code, excluding `node_modules` and build output. Files identified as browser/React components defer to `react`.

**Precision stance:** Dangerous sinks fire on non-constant input only; a constant `exec("git status")` is a note, not a finding. TLS and eval findings have no legitimate production form and fire hard.

Public grounding: Node.js security best-practices docs, OWASP command/code injection guidance, and the `NODE_TLS_REJECT_UNAUTHORIZED` footgun's long history in issue trackers.

---

## Critical

### `nodejs.shell-exec`

| | |
| --- | --- |
| **What** | Shell execution with constructed command strings |
| **Why** | `child_process.exec` / `execSync` always route through a shell — any non-constant fragment is command injection. The argv-based APIs exist precisely to avoid this |
| **Looks for** | `exec`/`execSync` (and `spawn` with `shell: true`) where the command contains template literals, concatenation, or variables |
| **Stays quiet when** | Fully constant command strings (note at low); `execFile`/`spawn` with argument arrays |
| **Public examples** | OWASP command injection; recurring npm-package CVEs from exec-with-interpolation |
| **Remediation** | Use `execFile` or `spawn` with a validated argument array |

---

## High

### `nodejs.dynamic-eval`

| | |
| --- | --- |
| **What** | Dynamic code evaluation on non-literal input |
| **Why** | `eval` / `new Function` / string-form timers on dynamic data is remote code execution when any request data reaches them |
| **Looks for** | `eval(X)`, `new Function(X)`, `setTimeout/setInterval("…")` string form, `vm.runIn*Context(X)` with non-literal X |
| **Stays quiet when** | Constant literals (still discouraged — note); build tooling/codegen files |
| **Public examples** | OWASP code injection; node-serialize RCE class |
| **Remediation** | Replace dynamic evaluation with explicit parsing (`JSON.parse`) or dispatch tables |

### `nodejs.tls-disabled`

| | |
| --- | --- |
| **What** | TLS certificate verification disabled |
| **Why** | `rejectUnauthorized: false` or `NODE_TLS_REJECT_UNAUTHORIZED=0` converts every outbound connection into a MITM opportunity — and the env-var form disables verification *process-wide*, including for libraries that did nothing wrong |
| **Looks for** | `rejectUnauthorized: false` in https/tls/axios/got/node-fetch agent options; `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` in code; the same env var set in committed run scripts |
| **Stays quiet when** | Test files targeting local self-signed fixtures; custom `ca:` provided instead of disabling verification |
| **Public examples** | Node TLS docs; the env-var footgun repeatedly copy-pasted from Stack Overflow |
| **Remediation** | Keep verification enabled; configure trusted roots via `ca:`/`NODE_EXTRA_CA_CERTS` |

### `nodejs.path-traversal`

| | |
| --- | --- |
| **What** | Filesystem access from user-influenced paths without confinement |
| **Why** | `fs.readFile(path.join(base, req.params.file))` serves `../../etc/passwd`; `path.join` normalizes but does not confine |
| **Looks for** | `fs.*` / `res.sendFile` calls whose path derives from request data (`req.params`, `req.query`, `req.body`, URL parsing) without a confinement check |
| **Stays quiet when** | Path resolved then verified against the base (`path.resolve` + prefix check with separator, or a vetted library); allowlist lookups mapping ids to fixed paths; express `res.sendFile` with the `root` option |
| **Public examples** | OWASP path traversal; recurring Express static-handler CVEs |
| **Remediation** | Resolve against a base directory and verify the result stays inside it, or map ids → paths through an allowlist |

---

## Medium

### `nodejs.weak-random-token`

| | |
| --- | --- |
| **What** | `Math.random()` feeding security identifiers |
| **Why** | `Math.random` is predictable; tokens, session ids, and reset codes built from it are guessable |
| **Looks for** | `Math.random()` results flowing into variables/fields named `token|secret|session|otp|code|nonce` or into auth-related responses |
| **Stays quiet when** | Non-security uses (jitter, sampling, shuffle, ids for DOM/logs); `crypto.randomBytes`/`randomUUID` used |
| **Public examples** | Node crypto docs; predictable-token disclosures |
| **Remediation** | Use `crypto.randomBytes` / `crypto.randomUUID` for anything an attacker benefits from guessing |

### `nodejs.vm-as-sandbox`

| | |
| --- | --- |
| **What** | `vm` module used to isolate untrusted code |
| **Why** | The Node docs say it plainly: `vm` is **not** a security mechanism — escapes via constructor chains are routine. LLM-gated: the module has legitimate non-security uses (template evaluation of trusted code) |
| **Looks for** | LLM-gated: `vm.runInNewContext`/`vm.Script` executing content from requests, user uploads, or database fields |
| **Stays quiet when** | Inputs are first-party/trusted (build scripts, templating over repo-owned content); a real isolation boundary (isolated-vm, worker + permission model, external sandbox service) wraps it |
| **Public examples** | Node `vm` docs disclaimer; vm2 escape CVE history (the maintained "secure" wrapper was repeatedly escaped, then deprecated) |
| **Remediation** | Treat untrusted code as needing process/VM-level isolation, not `vm`; or eliminate the need to execute it |

---

## Out of scope (owned elsewhere)

| Concern | Owner |
| --- | --- |
| React/JSX client code | `react` |
| Next.js config, middleware, Server Actions | `nextjs` |
| package.json lifecycle scripts, dependency policy | `npm` / `yarn` |
| TypeScript type-safety and config | `typescript` |
| Committed secrets | `security/secrets` |
