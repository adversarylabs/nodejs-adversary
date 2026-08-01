import { randomBytes } from "node:crypto";
export const token = randomBytes(16).toString("hex");
