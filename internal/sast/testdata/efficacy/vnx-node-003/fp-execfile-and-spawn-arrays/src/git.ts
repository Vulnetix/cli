import { execFile, spawn, execFileSync } from "child_process";

export function log(branch: string) {
  execFile("git", ["log", "--oneline", branch], () => {});
  spawn("ls", ["-la", `/srv/${branch}`]);
  return execFileSync("git", ["rev-parse", branch + "^{commit}"]);
}
