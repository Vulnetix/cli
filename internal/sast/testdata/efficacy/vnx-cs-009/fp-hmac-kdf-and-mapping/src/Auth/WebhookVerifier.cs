using System;
using System.Security.Cryptography;
using System.Text;

namespace Hooks.Auth
{
    public static class WebhookVerifier
    {
        public static byte[] LegacyHmac(byte[] key, byte[] body)
        {
            using var hmac = new HMACMD5(key);
            return hmac.ComputeHash(body);
        }

        public static byte[] Hmac(byte[] key, byte[] body) => HMACSHA1.HashData(key, body);

        public static KeyedHashAlgorithm Named() => (KeyedHashAlgorithm)CryptoConfig.CreateFromName("HMACSHA1");

        public static byte[] Derive(string password, byte[] salt)
        {
            using var kdf = new Rfc2898DeriveBytes(password, salt, 210_000, HashAlgorithmName.SHA1);
            return kdf.GetBytes(32);
        }

        public static HashAlgorithmName Parse(string name) => name switch
        {
            "sha1" => HashAlgorithmName.SHA1,
            "md5" => HashAlgorithmName.MD5,
            _ => HashAlgorithmName.SHA256,
        };

        public static object Modern() => CryptoConfig.CreateFromName("SHA256");

        public static string Explain(byte[] body)
        {
            var len = body.Length;
            return $"use SHA256 rather than {"MD5.Create()"} for {len} bytes";
        }
    }
}
