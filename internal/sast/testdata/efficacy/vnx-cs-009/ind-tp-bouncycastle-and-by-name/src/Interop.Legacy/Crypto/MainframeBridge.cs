using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;

namespace Interop.Legacy.Crypto
{
    public static class MainframeBridge
    {
        public static byte[] DigestRecord(byte[] record)
        {
~>            IDigest digest = new MD5Digest();
            digest.BlockUpdate(record, 0, record.Length);
            var output = new byte[digest.GetDigestSize()];
            digest.DoFinal(output, 0);
            return output;
        }

        public static IBlockCipher BatchCipher()
        {
~>            return new DesEdeEngine();
        }

        public static ISigner HostSigner()
        {
~>            return SignerUtilities.GetSigner("SHA1withRSA");
        }

        public static HashAlgorithm ResolveHasher()
        {
~>            return (HashAlgorithm)CryptoConfig.CreateFromName("MD5");
        }

        public static byte[] DeriveKey(string password, byte[] salt)
        {
~>            var pdb = new PasswordDeriveBytes(password, salt);
            return pdb.GetBytes(24);
        }

        public static void SignEnvelope(XmlDocument doc, RSA key)
        {
            var signed = new SignedXml(doc) { SigningKey = key };
~>            signed.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;
            var reference = new Reference("");
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signed.AddReference(reference);
            signed.ComputeSignature();
            doc.DocumentElement!.AppendChild(doc.ImportNode(signed.GetXml(), true));
        }
    }
}
