import crypto from "node:crypto";
~>const SHOPIFY_SECRET = "@@sample:shpss_[0-9a-f]{32}@@";
export const verify = (body: string, hmac: string) =>
  crypto.createHmac("sha256", SHOPIFY_SECRET).update(body).digest("base64") === hmac;
