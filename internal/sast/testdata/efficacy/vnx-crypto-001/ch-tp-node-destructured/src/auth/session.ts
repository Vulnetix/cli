import * as nodeCrypto from "crypto";
const { createHash } = require("node:crypto");

export function sessionId(user: { id: string }): string {
~>  return createHash("md5").update(user.id + Date.now()).digest("hex");
}

export function apiSignature(body: string): string {
~>  const h = nodeCrypto.createHash(`md5`);
  h.update(body);
  return h.digest("base64");
}
