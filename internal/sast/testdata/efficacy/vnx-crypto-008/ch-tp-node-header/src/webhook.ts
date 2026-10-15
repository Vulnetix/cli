import { createHmac } from "crypto";

export function verify(req: any, secret: string): boolean {
  const computed = createHmac("sha256", secret).update(req.rawBody).digest("hex");
~>  if (req.headers["x-signature"] !== computed) {
    return false;
  }
~>  return providedDigest === createHmac("sha1", secret).update(req.rawBody).digest("hex");
}
