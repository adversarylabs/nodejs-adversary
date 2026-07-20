import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
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
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
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
    readonly description: "Reviews Node.js for dynamic code execution, shell injection, and disabled TLS verification.";
    readonly files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"];
    readonly rules: [{
        readonly id: "nodejs.dynamic-eval";
        readonly title: "Application executes dynamically constructed JavaScript";
        readonly summary: "Application executes dynamically constructed JavaScript";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Application executes dynamically constructed JavaScript weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Replace dynamic evaluation with explicit parsing or dispatch.";
        readonly complexity: "small";
        readonly tags: ["security", "dynamic-eval"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "\\b(?:eval|new\\s+Function)\\s*\\(";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "nodejs.shell-exec";
        readonly title: "Node.js constructs a shell command from input";
        readonly summary: "Node.js constructs a shell command from input";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Node.js constructs a shell command from input weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Use execFile or spawn with a validated argument array.";
        readonly complexity: "small";
        readonly tags: ["security", "shell-exec"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "(?:exec|execSync)\\s*\\(\\s*`[^`]*\\$\\{";
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
        readonly whyItMatters: "Node.js disables TLS certificate verification weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Keep verification enabled and configure trusted roots.";
        readonly complexity: "small";
        readonly tags: ["security", "tls-disabled"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"];
            readonly pattern: {
                readonly pattern: "NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*[\"']?0";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
