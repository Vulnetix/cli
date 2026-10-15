import { createHash } from "crypto";

export function signRequest(body: string, secret: string): string {
~>  return createHash('sha1')
    .update(body + secret)
    .digest("hex");
}
