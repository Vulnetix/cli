import { Issuer } from 'openid-client';

~>process.env["AUTHLIB_INSECURE_TRANSPORT"] = "true";

export async function discover(url: string) {
  return Issuer.discover(url);
}
