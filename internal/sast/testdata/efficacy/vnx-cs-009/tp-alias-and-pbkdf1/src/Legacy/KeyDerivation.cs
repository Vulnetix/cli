using System.Security.Cryptography;
using LegacyHash = System.Security.Cryptography.MD5;
using OldCipher = System.Security.Cryptography.TripleDESCryptoServiceProvider;

namespace Archive.Legacy
{
    internal static class KeyDerivation
    {
        public static byte[] DeriveKey(string password, byte[] salt)
        {
~>            var kdf = new PasswordDeriveBytes(password, salt);
            return kdf.GetBytes(32);
        }

        public static byte[] Digest(byte[] data)
        {
~>            using var h = LegacyHash.Create();
            return h.ComputeHash(data);
        }

        public static SymmetricAlgorithm Cipher()
        {
~>            return new OldCipher();
        }
    }
}
