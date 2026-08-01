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

const SOURCE_FILES = ["**/*.js", "**/*.mjs", "**/*.cjs", "**/*.ts"] as const;

export const spec = {
  "id": "nodejs",
  "displayName": "Node.js",
  "description": "Reviews Node.js for dynamic code execution, shell injection, and disabled TLS verification.",
  "files": [...SOURCE_FILES],
  "rules": [
    {
      "id": "nodejs.shell-exec",
      "title": "Node.js constructs a shell command from input",
      "summary": "Node.js constructs a shell command from input",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "child_process.exec/execSync always route through a shell — non-constant fragments are command injection.",
      "impact": "Remote command execution when request data reaches the command string.",
      "recommendation": "Use execFile or spawn with a validated argument array.",
      "complexity": "small",
      "tags": ["security", "shell-exec"],
      "match": {
        "kind": "content",
        "files": [...SOURCE_FILES],
        "pattern": {
          "pattern": "(?:exec|execSync)\\s*\\(\\s*[`'\"][^`'\"]*(?:\\$\\{|\\+)|(?:spawn|spawnSync)\\s*\\([^)]*shell\\s*:\\s*true",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "nodejs.dynamic-eval",
      "title": "Application executes dynamically constructed JavaScript",
      "summary": "Application executes dynamically constructed JavaScript",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "eval/new Function/string-form timers on dynamic data enable remote code execution.",
      "impact": "Attacker-controlled strings become running code in the Node process.",
      "recommendation": "Replace dynamic evaluation with explicit parsing (JSON.parse) or dispatch tables.",
      "complexity": "small",
      "tags": ["security", "dynamic-eval"],
      "match": {
        "kind": "content",
        "files": [...SOURCE_FILES],
        "pattern": {
          "pattern": "\\b(?:eval|new\\s+Function)\\s*\\(|(?:setTimeout|setInterval)\\s*\\(\\s*[\"'`]",
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
      "whyItMatters": "rejectUnauthorized: false or NODE_TLS_REJECT_UNAUTHORIZED=0 converts outbound TLS into MITM opportunities.",
      "impact": "Credentials and response bodies can be intercepted on any HTTPS call from the process.",
      "recommendation": "Keep verification enabled; configure trusted roots via ca: or NODE_EXTRA_CA_CERTS.",
      "complexity": "small",
      "tags": ["security", "tls-disabled"],
      "match": {
        "kind": "content",
        "files": [...SOURCE_FILES],
        "pattern": {
          "pattern": "rejectUnauthorized\\s*:\\s*false|NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*[\"']?0",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "nodejs.path-traversal",
      "title": "Filesystem access from request-influenced paths",
      "summary": "Filesystem access from request-influenced paths",
      "category": "security",
      "severity": "high",
      "confidence": "medium",
      "whyItMatters": "path.join does not confine; request-derived path segments enable directory traversal.",
      "impact": "Read or write of files outside the intended base directory.",
      "recommendation": "Resolve against a base directory and verify the result stays inside it, or map ids to paths through an allowlist.",
      "complexity": "small",
      "tags": ["security", "path-traversal"],
      "match": {
        "kind": "content",
        "files": [...SOURCE_FILES],
        "pattern": {
          "pattern": "(?:fs\\.[\\w]+|readFile(?:Sync)?|writeFile(?:Sync)?|createReadStream|createWriteStream|sendFile)\\s*\\([\\s\\S]{0,120}req\\.(?:params|query|body)|path\\.join\\s*\\([^)]*req\\.(?:params|query|body)",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "nodejs.weak-random-token",
      "title": "Math.random used for security identifiers",
      "summary": "Math.random used for security identifiers",
      "category": "security",
      "severity": "medium",
      "confidence": "medium",
      "whyItMatters": "Math.random is predictable; tokens and session ids built from it are guessable.",
      "impact": "Account takeover via predictable reset codes, session ids, or API tokens.",
      "recommendation": "Use crypto.randomBytes or crypto.randomUUID for anything an attacker benefits from guessing.",
      "complexity": "small",
      "tags": ["security", "weak-random"],
      "match": {
        "kind": "content",
        "files": [...SOURCE_FILES],
        "pattern": {
          "pattern": "(?:(?:token|secret|session|otp|nonce|resetCode|authCode)\\s*[=:]\\s*[\\s\\S]{0,40}Math\\.random\\s*\\(|Math\\.random\\s*\\([\\s\\S]{0,40}(?:token|secret|session|otp|nonce))",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "nodejs.vm-as-sandbox",
      "title": "vm module used as a security sandbox",
      "summary": "vm module used as a security sandbox",
      "category": "security",
      "severity": "medium",
      "confidence": "medium",
      "whyItMatters": "Node documents that vm is not a security mechanism; constructor-chain escapes are routine.",
      "impact": "Untrusted code breakout from an assumed sandbox into the host process.",
      "recommendation": "Use process/VM-level isolation (or eliminate untrusted execution); do not treat vm as a security boundary.",
      "complexity": "medium",
      "tags": ["security", "vm"],
      "match": {
        "kind": "content",
        "files": [...SOURCE_FILES],
        "pattern": {
          "pattern": "vm\\.(?:runInNewContext|runInContext|runInThisContext|Script)\\s*\\(",
          "flags": "i"
        },
        "requires": []
      }
    }
  ]
} as const satisfies AdversarySpec;
