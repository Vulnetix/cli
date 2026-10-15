using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;

namespace Interop.Legacy
{
    public static class PartnerChannel
    {
        public static byte[] Fingerprint(byte[] data)
        {
~>            IDigest digest = new Sha1Digest();
            digest.BlockUpdate(data, 0, data.Length);
            var result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }

        public static ISigner PartnerSigner()
        {
~>            return SignerUtilities.GetSigner("SHA1withRSA");
        }

        public static IBufferedCipher PartnerCipher()
        {
~>            return CipherUtilities.GetCipher("DESede/CBC/PKCS7Padding");
        }

        public static byte[] Md5(byte[] data)
        {
~>            return DigestUtilities.CalculateDigest("MD5", data);
        }

        public static HashAlgorithm ByName()
        {
~>            return (HashAlgorithm)CryptoConfig.CreateFromName("SHA1");
        }

        public static HashAlgorithm FullName()
        {
~>            return HashAlgorithm.Create("@@sample:S[y]st[e]m[.][S]ec[u]ri[t]y[.][C]ry[p]to[g]ra[p]hy[.]MD[5]@@");
        }
    }
}
