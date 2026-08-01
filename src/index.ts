#!/usr/bin/env node

import { Adversary } from "@adversarylabs/sdk";
import { analyzeRepository } from "./analyze.js";
import { registerRules } from "./rules.js";

export function createApp(): Adversary {
  const app = new Adversary({ name: "lang/nodejs", version: "0.0.4", review: { maximumFindings: 12 } });
  registerRules(app);
  app.rule("nodejs.review", async (ctx) => analyzeRepository(ctx));
  return app;
}

if (process.argv[1] !== undefined && import.meta.url === new URL(process.argv[1], "file:").href) {
  await createApp().runFromEnvironment();
}
