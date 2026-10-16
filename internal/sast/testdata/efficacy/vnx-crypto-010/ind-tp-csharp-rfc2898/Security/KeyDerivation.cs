using System.Security.Cryptography;
using System.Text;

namespace Acme.Security
{
    public static class KeyDerivation
    {
        public static byte[] DeriveKey(string password)
        {
~>            using var kdf = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes("acme-app-salt"), 100000, HashAlgorithmName.SHA256);
            return kdf.GetBytes(32);
        }

        public static ICryptoTransform LegacyEncryptor(byte[] key)
        {
            var aes = Aes.Create();
            aes.Key = key;
~>            aes.IV = new byte[16];
            return aes.CreateEncryptor();
        }
    }
}
