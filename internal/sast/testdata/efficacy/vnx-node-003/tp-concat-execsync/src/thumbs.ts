import * as cp from "node:child_process";

export function thumbnail(file: string): Buffer {
~>  return cp.execSync("convert " + file + " -resize 64x64 png:-");
}
