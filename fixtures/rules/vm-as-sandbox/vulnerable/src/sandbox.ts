import vm from "node:vm";
export const run = (code: string) => vm.runInNewContext(code, {});
