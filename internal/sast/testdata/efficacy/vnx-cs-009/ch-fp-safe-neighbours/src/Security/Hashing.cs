using System;
using System.Security.Cryptography;
using System.Text;

namespace Security
{
    public sealed class Hashing
    {
        public byte[] Sha256(byte[] data) => SHA256.HashData(data);

        public byte[] Sha512(byte[] data)
        {
            using var sha = SHA512.Create();
            return sha.ComputeHash(data);
        }

        public byte[] Totp(byte[] key, byte[] counter)
        {
            using var hmac = new HMACSHA1(key);
            return hmac.ComputeHash(counter);
        }

        public byte[] Webhook(byte[] key, byte[] body)
        {
            using var inc = IncrementalHash.CreateHMAC(@@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A1@@, key);
            inc.AppendData(body);
            return inc.GetHashAndReset();
        }

        public byte[] Derive(string password, byte[] salt)
        {
            return @@sample:R[f]c2[8]98[D]er[i]ve[B]yt[e]s[.][P]bk[d]f2@@(password, salt, 600000, @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A2[5]6@@, 32);
        }

        public byte[] Wrap(RSA rsa, byte[] key)
        {
            return rsa.Encrypt(key, @@sample:R[S]AE[n]cr[y]pt[i]on[P]ad[d]in[g][.]O[a]ep[S]HA[1]@@);
        }

        public byte[] Sign(RSA rsa, byte[] payload)
        {
            return rsa.SignData(payload, @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A2[5]6@@, RSASignaturePadding.Pss);
        }

        public bool IsLegacy(HashAlgorithmName name)
        {
            return name == @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A1@@ || name == @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]M[D]5@@;
        }

        public Aes Cipher()
        {
            var aes = Aes.Create();
            aes.KeySize = 256;
            return aes;
        }

        public byte[] Hmac(byte[] key, byte[] data) => HMACMD5.HashData(key, data);
    }
}
