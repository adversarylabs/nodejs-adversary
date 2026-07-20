import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

export const spec = {
  "id": "nodejs",
  "displayName": "Node.js",
  "description": "Reviews Node.js for dynamic code execution, shell injection, and disabled TLS verification.",
  "files": [
    "**/*.js",
    "**/*.mjs",
    "**/*.cjs",
    "**/*.ts"
  ],
  "rules": [
    {
      "id": "nodejs.dynamic-eval",
      "title": "Application executes dynamically constructed JavaScript",
      "summary": "Application executes dynamically constructed JavaScript",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Application executes dynamically constructed JavaScript weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Replace dynamic evaluation with explicit parsing or dispatch.",
      "complexity": "small",
      "tags": [
        "security",
        "dynamic-eval"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.js",
          "**/*.mjs",
          "**/*.cjs",
          "**/*.ts"
        ],
        "pattern": {
          "pattern": "\\b(?:eval|new\\s+Function)\\s*\\(",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "nodejs.shell-exec",
      "title": "Node.js constructs a shell command from input",
      "summary": "Node.js constructs a shell command from input",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "Node.js constructs a shell command from input weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Use execFile or spawn with a validated argument array.",
      "complexity": "small",
      "tags": [
        "security",
        "shell-exec"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.js",
          "**/*.mjs",
          "**/*.cjs",
          "**/*.ts"
        ],
        "pattern": {
          "pattern": "(?:exec|execSync)\\s*\\(\\s*`[^`]*\\$\\{",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "nodejs.tls-disabled",
      "title": "Node.js disables TLS certificate verification",
      "summary": "Node.js disables TLS certificate verification",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Node.js disables TLS certificate verification weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Keep verification enabled and configure trusted roots.",
      "complexity": "small",
      "tags": [
        "security",
        "tls-disabled"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.js",
          "**/*.mjs",
          "**/*.cjs",
          "**/*.ts"
        ],
        "pattern": {
          "pattern": "NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*[\"']?0",
          "flags": "i"
        },
        "requires": []
      }
    }
  ]
} as const satisfies AdversarySpec;
