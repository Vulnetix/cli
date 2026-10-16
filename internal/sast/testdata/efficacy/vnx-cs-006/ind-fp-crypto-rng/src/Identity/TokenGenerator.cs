using System;
using System.Security.Cryptography;

namespace Identity
{
    public static class TokenGenerator
    {
        public static string ResetToken()
        {
            byte[] tokenBytes = RandomNumberGenerator.GetBytes(32);
            return Convert.ToBase64String(tokenBytes);
        }

        public static int Otp() => RandomNumberGenerator.GetInt32(100000, 1000000);

        public static byte[] NewKey()
        {
            var key = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
            }
            return key;
        }

        public static byte[] Salt()
        {
            var salt = new byte[16];
            RandomNumberGenerator.Fill(salt);
            return salt;
        }
    }
}
