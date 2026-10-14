using System;
using System.Security.Cryptography;
using System.Text;

namespace Payments.Crypto
{
    public static class ModernCrypto
    {
        public static byte[] Digest(byte[] data) => SHA256.HashData(data);

        public static byte[] Digest512(byte[] data)
        {
            using var sha = SHA512.Create();
            return sha.ComputeHash(data);
        }

        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] tag)
        {
            var ciphertext = new byte[plaintext.Length];
            using var gcm = new AesGcm(key, 16);
            gcm.Encrypt(nonce, plaintext, ciphertext, tag);
            return ciphertext;
        }

        public static SymmetricAlgorithm Block() => Aes.Create();

        public static byte[] Password(string password, byte[] salt)
        {
            return Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
        }

        // TOTP (RFC 6238) is defined over HMAC-SHA1; HMAC does not rely on collision resistance.
        public static byte[] Totp(byte[] secret, byte[] counter)
        {
            using var hmac = new HMACSHA1(secret);
            return hmac.ComputeHash(counter);
        }

        public static byte[] Mac(byte[] key, byte[] data)
        {
            using var h = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, key);
            h.AppendData(data);
            return h.GetHashAndReset();
        }

        public static byte[] Wrap(RSA rsa, byte[] key)
        {
            return rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA1);
        }

        public static byte[] Sign(RSA rsa, byte[] payload)
        {
            return rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }

        public static HashAlgorithm Hasher() => HashAlgorithm.Create("SHA256");

        public static HashAlgorithm Configured(string name) => HashAlgorithm.Create(name);
    }
}
