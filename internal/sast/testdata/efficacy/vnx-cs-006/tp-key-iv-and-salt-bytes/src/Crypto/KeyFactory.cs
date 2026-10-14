using System;
using System.Security.Cryptography;

namespace Crypto
{
    public class KeyFactory
    {
        public byte[] Fresh()
        {
            var key = new byte[32];
~>            new Random().NextBytes(key);
            return key;
        }

        public Aes Cipher(byte[] secretKey)
        {
            var buffer = new byte[16];
            var rnd = new Random(Environment.TickCount);
~>            rnd.NextBytes(buffer);
            var aes = Aes.Create();
            aes.Key = secretKey;
            aes.IV = buffer;
            return aes;
        }

        public string Hash(string password)
        {
            var salt = new byte[16];
~>            Random.Shared.NextBytes(salt);
            using var kdf = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
            return Convert.ToBase64String(kdf.GetBytes(32));
        }
    }
}
