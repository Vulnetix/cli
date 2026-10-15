import crypto from "node:crypto";

export function checkDownload(buf: Buffer, published: string): boolean {
  const actual = crypto.createHash("sha256").update(buf).digest("hex");
~>  return actual.substring(0, 12) === published;
}

export function checkSignature(req: any, secret: string): void {
  const signature = req.get("x-signature");
  const expected = crypto.createHmac("sha256", secret).update(req.rawBody).digest("hex");
~>  if (signature !== undefined && signature !== expected) {
    throw new Error("bad signature");
  }
}
