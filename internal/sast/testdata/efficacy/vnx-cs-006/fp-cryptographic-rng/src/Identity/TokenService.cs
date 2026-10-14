using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;

namespace Identity
{
    public class TokenService
    {
        private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        public string CreateResetToken()
        {
            byte[] tokenBytes = RandomNumberGenerator.GetBytes(32);
            return Convert.ToBase64String(tokenBytes);
        }

        public int CreateOtp()
        {
            return RandomNumberGenerator.GetInt32(100000, 1000000);
        }

        public byte[] NewSalt()
        {
            var salt = new byte[16];
            _rng.GetBytes(salt);
            return salt;
        }

        public byte[] NewKey()
        {
            using var provider = new RNGCryptoServiceProvider();
            var key = new byte[32];
            provider.GetBytes(key);
            return key;
        }

        public byte[] BouncyNonce()
        {
            SecureRandom random = new SecureRandom();
            var nonce = new byte[12];
            random.NextBytes(nonce);
            return nonce;
        }
    }
}
