import https from "https";

export const agent = new https.Agent({
  ca: process.env.CA_PEM,
  rejectUnauthorized: true,
  checkServerIdentity: (host, cert) => verifyPin(host, cert),
});
