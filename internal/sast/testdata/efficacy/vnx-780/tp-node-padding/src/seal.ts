import crypto from "crypto";
import NodeRSA from "node-rsa";

export function seal(publicKey: string, data: Buffer): Buffer {
  return crypto.publicEncrypt(
    {
      key: publicKey,
~>      padding: @@sample:c[r]yp[t]o[.][c]on[s]ta[n]ts[.]RS[A][_]P[K]CS[1][_]P[A]DD[I]NG@@,
    },
    data,
  );
}

export function open(privateKey: string, data: Buffer): Buffer {
~>  return crypto.privateDecrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, data);
}

~>const legacy = new NodeRSA(pem, "pkcs8-public", { encryptionScheme: "pkcs1" });
~>legacy.setOptions({ encryptionScheme: 'pkcs1' });
