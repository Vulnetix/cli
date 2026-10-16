using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Licensing.Signing
{
    public sealed class LicenseSigner
    {
        private static readonly HashAlgorithmName LegacyAlg = HashAlgorithmName.SHA1;

        private readonly RSA _rsa;

        public LicenseSigner(RSA rsa) => _rsa = rsa;

        public byte[] Sign(byte[] payload)
        {
~>            return _rsa.SignData(payload, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        }

        public bool VerifyOld(byte[] payload, byte[] signature)
        {
~>            return _rsa.VerifyData(payload, signature, LegacyAlg, RSASignaturePadding.Pkcs1);
        }

        public static X509Certificate2 IssueDeviceCert(RSA key, string subject)
        {
~>            var req = new CertificateRequest($"CN={subject}", key, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            return req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(5));
        }

        public static byte[] Fingerprint(byte[] blob)
        {
~>            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            hasher.AppendData(blob);
            return hasher.GetHashAndReset();
        }
    }
}
