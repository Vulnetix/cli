import * as nodeCrypto from "crypto";
const { createHash } = require("node:crypto");

export function assetId(path: string): string {
~>  return createHash("md5").update(path).digest("hex");
}

export function bucketFor(name: string): string {
~>  const h = nodeCrypto.createHash(`md5`);
  h.update(name);
  return h.digest("base64");
}
