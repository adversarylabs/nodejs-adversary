import fs from "node:fs";
export const read = (req) => fs.readFile(path.join(base, req.params.file));
