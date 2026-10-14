using System.IO;
using System.Security.Cryptography;

namespace Payments.Crypto
{
    internal static class LegacyCipher
    {
        public static byte[] EncryptCard(byte[] pan, byte[] key, byte[] iv)
        {
~>            using var des = new DESCryptoServiceProvider();
            des.Key = key;
            des.IV = iv;
            using var enc = des.CreateEncryptor();
            return enc.TransformFinalBlock(pan, 0, pan.Length);
        }

        public static ICryptoTransform TripleDesDecryptor(byte[] key)
        {
~>            var tdes = new TripleDESCryptoServiceProvider
            {
                Key = key,
                Mode = CipherMode.CBC,
            };
            return tdes.CreateDecryptor();
        }

        public static SymmetricAlgorithm Rc2()
        {
~>            return new RC2CryptoServiceProvider() { KeySize = 128 };
        }

        public static byte[] Checksum(Stream s)
        {
~>            var sha = new SHA1Managed();
            return sha.ComputeHash(s);
        }

        public static byte[] Md5(byte[] data)
        {
~>            MD5CryptoServiceProvider provider = new();
            return provider.ComputeHash(data);
        }

        public static byte[] Cng(byte[] data)
        {
~>            using var h = new System.Security.Cryptography.SHA1Cng();
            return h.ComputeHash(data);
        }

        public static SymmetricAlgorithm Pick(string name)
        {
            switch (name)
            {
                case "des":
~>                    return DES.Create();
                case "3des":
~>                    return TripleDES.Create();
                case "rc2":
~>                    return RC2.Create();
                default:
                    return Aes.Create();
            }
        }
    }
}
