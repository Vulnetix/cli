using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;

namespace Gateway.Interop
{
    public static class BcLegacy
    {
        public static byte[] Md5(byte[] input)
        {
~>            IDigest digest = new MD5Digest();
            digest.BlockUpdate(input, 0, input.Length);
            var output = new byte[digest.GetDigestSize()];
            digest.DoFinal(output, 0);
            return output;
        }

~>        public static IDigest Sha1() => new Sha1Digest();

~>        public static IBlockCipher TripleDes() => new DesEdeEngine();

~>        public static IStreamCipher Rc4() => new RC4Engine();

~>        public static IDigest Named() => DigestUtilities.GetDigest("MD5");

        public static IBufferedCipher Des()
        {
~>            return CipherUtilities.GetCipher("DES/CBC/PKCS7Padding");
        }

        public static ISigner Signer()
        {
~>            return SignerUtilities.GetSigner("SHA1withRSA");
        }

~>        public static IDigest Dashed() => DigestUtilities.GetDigest("SHA-1");

~>        public static ISigner LowerSigner() => SignerUtilities.GetSigner("sha-1withecdsa");

~>        public static IBufferedCipher Stream() => CipherUtilities.GetCipher("ARCFOUR");
    }
}
