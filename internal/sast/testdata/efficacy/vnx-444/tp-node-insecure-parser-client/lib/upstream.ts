import https from "https";

export function callLegacy(path: string, body: Buffer) {
  const req = https.request({
    host: "legacy.internal",
    path,
    method: "POST",
~>    insecureHTTPParser   :   true,
  });
  req.end(body);
  return req;
}
