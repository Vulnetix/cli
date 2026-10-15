export const crypto = {
  signingKeyPath: '/etc/acme/keys/signing-private.pem',
  encryptionKeyId: 'arn:aws:kms:eu-west-1:123456789012:key/mrk-1234abcd',
  jwtSecretEnv: 'ACME_JWT_SECRET_VALUE',
  secretKeyHeader: 'X-Acme-Secret-Key-Name',
};
