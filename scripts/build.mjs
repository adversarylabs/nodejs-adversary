import { build } from "esbuild";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });

await build({
  entryPoints: ["src/index.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  outfile: "dist/index.js",
  banner: {
    js: "import { createRequire as __nodejsCreateRequire } from 'node:module'; const require = __nodejsCreateRequire(import.meta.url);",
  },
});

await mkdir("schemas", { recursive: true });
await copyFile(
  "node_modules/@adversarylabs/sdk/schemas/adversary.review.v1.schema.json",
  "schemas/adversary.review.v1.schema.json",
);

const notices = [
  ["@adversarylabs/sdk", "MIT", "node_modules/@adversarylabs/sdk/LICENSE"],
  ["ajv", "MIT", "node_modules/ajv/LICENSE"],
  ["fast-deep-equal", "MIT", "node_modules/fast-deep-equal/LICENSE"],
  ["fast-uri", "BSD-3-Clause", "node_modules/fast-uri/LICENSE"],
  ["json-schema-traverse", "MIT", "node_modules/json-schema-traverse/LICENSE"],
  ["require-from-string", "MIT", "node_modules/require-from-string/license"],
  ["yaml", "ISC", "node_modules/yaml/LICENSE"],
];
const noticeSections = await Promise.all(notices.map(async ([name, license, path]) =>
  `## ${name} (${license})\n\n${(await readFile(path, "utf8")).trim()}`,
));
await writeFile("THIRD_PARTY_NOTICES.md", `# Third-party notices\n\n${noticeSections.join("\n\n")}\n`);
