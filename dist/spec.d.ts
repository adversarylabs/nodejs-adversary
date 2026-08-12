import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    anchors?: MatchExpression[];
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
interface EventListenerCleanupMatch {
    kind: "event-listener-cleanup";
    files: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | MissingFileMatch | EventListenerCleanupMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "nodejs";
    readonly displayName: "Node.js";
    readonly description: "Reviews Node.js for security hazards and lifecycle cleanup leaks.";
    readonly files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"];
    readonly rules: [{
        readonly id: "nodejs.shell-exec";
        readonly title: "Node.js constructs a shell command from input";
        readonly summary: "Node.js constructs a shell command from input";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "child_process.exec/execSync always route through a shell — non-constant fragments are command injection.";
        readonly impact: "Remote command execution when request data reaches the command string.";
        readonly recommendation: "Use execFile or spawn with a validated argument array.";
        readonly complexity: "small";
        readonly tags: ["security", "shell-exec"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "(?:exec|execSync)\\s*\\(\\s*[`'\"][^`'\"]*(?:\\$\\{|\\+)|(?:spawn|spawnSync)\\s*\\([^)]*shell\\s*:\\s*true";
                readonly flags: "i";
            };
            readonly anchors: [{
                readonly pattern: "(?:exec|execSync|spawn|spawnSync)\\s*\\(";
                readonly flags: "i";
            }, {
                readonly pattern: "\\$\\{|\\+|shell\\s*:\\s*true";
                readonly flags: "i";
            }];
            readonly requires: [];
        };
    }, {
        readonly id: "nodejs.dynamic-eval";
        readonly title: "Application executes dynamically constructed JavaScript";
        readonly summary: "Application executes dynamically constructed JavaScript";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "eval/new Function/string-form timers on dynamic data enable remote code execution.";
        readonly impact: "Attacker-controlled strings become running code in the Node process.";
        readonly recommendation: "Replace dynamic evaluation with explicit parsing (JSON.parse) or dispatch tables.";
        readonly complexity: "small";
        readonly tags: ["security", "dynamic-eval"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "\\b(?:eval|new\\s+Function)\\s*\\(|(?:setTimeout|setInterval)\\s*\\(\\s*[\"'`]";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "nodejs.tls-disabled";
        readonly title: "Node.js disables TLS certificate verification";
        readonly summary: "Node.js disables TLS certificate verification";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "rejectUnauthorized: false or NODE_TLS_REJECT_UNAUTHORIZED=0 converts outbound TLS into MITM opportunities.";
        readonly impact: "Credentials and response bodies can be intercepted on any HTTPS call from the process.";
        readonly recommendation: "Keep verification enabled; configure trusted roots via ca: or NODE_EXTRA_CA_CERTS.";
        readonly complexity: "small";
        readonly tags: ["security", "tls-disabled"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "rejectUnauthorized\\s*:\\s*false|NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*[\"']?0";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "nodejs.path-traversal";
        readonly title: "Filesystem access from request-influenced paths";
        readonly summary: "Filesystem access from request-influenced paths";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "medium";
        readonly whyItMatters: "path.join does not confine; request-derived path segments enable directory traversal.";
        readonly impact: "Read or write of files outside the intended base directory.";
        readonly recommendation: "Resolve against a base directory and verify the result stays inside it, or map ids to paths through an allowlist.";
        readonly complexity: "small";
        readonly tags: ["security", "path-traversal"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "(?:fs\\.[\\w]+|readFile(?:Sync)?|writeFile(?:Sync)?|createReadStream|createWriteStream|sendFile)\\s*\\([\\s\\S]{0,120}req\\.(?:params|query|body)|path\\.join\\s*\\([^)]*req\\.(?:params|query|body)";
                readonly flags: "i";
            };
            readonly anchors: [{
                readonly pattern: "(?:fs\\.[\\w]+|readFile(?:Sync)?|writeFile(?:Sync)?|createReadStream|createWriteStream|sendFile|path\\.join)\\s*\\(";
                readonly flags: "i";
            }, {
                readonly pattern: "req\\.(?:params|query|body)";
                readonly flags: "i";
            }];
            readonly requires: [];
        };
    }, {
        readonly id: "nodejs.weak-random-token";
        readonly title: "Math.random used for security identifiers";
        readonly summary: "Math.random used for security identifiers";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "medium";
        readonly whyItMatters: "Math.random is predictable; tokens and session ids built from it are guessable.";
        readonly impact: "Account takeover via predictable reset codes, session ids, or API tokens.";
        readonly recommendation: "Use crypto.randomBytes or crypto.randomUUID for anything an attacker benefits from guessing.";
        readonly complexity: "small";
        readonly tags: ["security", "weak-random"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "(?:(?:token|secret|session|otp|nonce|resetCode|authCode)\\s*[=:]\\s*[\\s\\S]{0,40}Math\\.random\\s*\\(|Math\\.random\\s*\\([\\s\\S]{0,40}(?:token|secret|session|otp|nonce))";
                readonly flags: "i";
            };
            readonly anchors: [{
                readonly pattern: "(?:token|secret|session|otp|nonce|resetCode|authCode)\\s*[=:]|Math\\.random\\s*\\(";
                readonly flags: "i";
            }];
            readonly requires: [];
        };
    }, {
        readonly id: "nodejs.vm-as-sandbox";
        readonly title: "vm module used as a security sandbox";
        readonly summary: "vm module used as a security sandbox";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "medium";
        readonly whyItMatters: "Node documents that vm is not a security mechanism; constructor-chain escapes are routine.";
        readonly impact: "Untrusted code breakout from an assumed sandbox into the host process.";
        readonly recommendation: "Use process/VM-level isolation (or eliminate untrusted execution); do not treat vm as a security boundary.";
        readonly complexity: "medium";
        readonly tags: ["security", "vm"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "vm\\.(?:runInNewContext|runInContext|runInThisContext|Script)\\s*\\(";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "nodejs.event-listener-cleanup";
        readonly title: "Lifecycle cleanup leaves sibling EventEmitter listeners attached";
        readonly summary: "Lifecycle cleanup leaves sibling EventEmitter listeners attached";
        readonly category: "reliability";
        readonly severity: "medium";
        readonly confidence: "medium";
        readonly whyItMatters: "A once listener removes only the registration that fired. Sibling lifecycle listeners using the same callback keep its closure and resources alive unless cleanup unregisters them too.";
        readonly impact: "Long-lived or reused emitters retain stale callbacks, causing memory/resource leaks and cleanup to run again on later events.";
        readonly recommendation: "In the shared cleanup callback, call removeListener or off for every lifecycle event that registered it.";
        readonly complexity: "trivial";
        readonly tags: ["reliability", "event-emitter", "resource-leak"];
        readonly match: {
            readonly kind: "event-listener-cleanup";
            readonly files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"];
        };
    }];
};
export {};
