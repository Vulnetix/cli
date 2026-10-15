using System.Security.Cryptography;

namespace Auth
{
    public sealed class OtpService
    {
        private static readonly HashAlgorithmName OtpHash = @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A1@@;

        public byte[] Code(byte[] secret, byte[] counter)
        {
            using var inc = IncrementalHash.CreateHMAC(OtpHash, secret);
            inc.AppendData(counter);
            return inc.GetHashAndReset();
        }

        public byte[] LegacyKey(string password, byte[] salt)
        {
            var kdfHash = @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A1@@;
            return @@sample:R[f]c2[8]98[D]er[i]ve[B]yt[e]s[.][P]bk[d]f2@@(password, salt, 310000, kdfHash, 32);
        }

        public byte[] Sign(RSA rsa, byte[] data)
        {
            var strong = @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A2[5]6@@;
            return rsa.SignData(data, strong, RSASignaturePadding.Pss);
        }

        public bool Matches(HashAlgorithmName requested) => requested == OtpHash;
    }
}
