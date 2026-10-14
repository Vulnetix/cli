using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Licensing.Signing
{
    public sealed class TokenSigner
    {
        private readonly RSA _rsa;

        public TokenSigner(RSA rsa) => _rsa = rsa;

        public byte[] Sign(byte[] payload)
        {
~>            return _rsa.SignData(payload, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        }

        public bool Verify(byte[] payload, byte[] signature)
        {
            return _rsa.VerifyData(
                payload,
                signature,
~>                HashAlgorithmName.SHA1,
                RSASignaturePadding.Pkcs1);
        }

        public byte[] Digest(byte[] data)
        {
~>            using var h = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            h.AppendData(data);
            return h.GetHashAndReset();
        }

        public CertificateRequest Request(string subject)
        {
~>            return new CertificateRequest(subject, _rsa, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        }

        public byte[] SignDigest(byte[] digest)
        {
~>            return _rsa.SignHash(digest, CryptoConfig.MapNameToOID("SHA1"));
        }

        public byte[] Legacy(byte[] digest)
        {
            var formatter = new RSAPKCS1SignatureFormatter(_rsa);
~>            formatter.SetHashAlgorithm("SHA1");
            return formatter.CreateSignature(digest);
        }

        public void SignXml(XmlDocument doc)
        {
            var signed = new SignedXml(doc) { SigningKey = _rsa };
~>            signed.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;
            var reference = new Reference("")
            {
~>                DigestMethod = SignedXml.XmlDsigSHA1Url,
            };
            signed.AddReference(reference);
            signed.ComputeSignature();
        }

        public void SignXmlDsa(SignedXml signed)
        {
~>            signed.SignedInfo.SignatureMethod = SignedXml.XmlDsigDSAUrl;
            signed.ComputeSignature();
        }
    }
}
