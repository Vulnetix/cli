using System.Security.Cryptography;

namespace Acme.Security
{
    public sealed class Envelope
    {
        public static (byte[] Iv, ICryptoTransform Enc) NewEncryptor(byte[] key)
        {
            var aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();
            return (aes.IV, aes.CreateEncryptor());
        }

        public static ICryptoTransform Decryptor(byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            return aes.CreateDecryptor(key, iv);
        }

        public static byte[] Hash(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            return Rfc2898DeriveBytes.Pbkdf2(password, salt, 210000, HashAlgorithmName.SHA512, 32);
        }
    }
}
