import { createHmac, timingSafeEqual } from "node:crypto";

export function handleWebhook(secret: string, body: string, header: string): unknown {
  const expected = createHmac("sha256", secret).update(body).digest();
  const given = Buffer.from(header, "hex");
~>  timingSafeEqual(expected, given);
  return JSON.parse(body);
}
