using System.Security.Cryptography;

namespace Licensing
{
    public sealed class LicenseVerifier
    {
        public bool Verify(RSA publicKey, byte[] license, byte[] signature)
        {
            var hashAlgorithm = @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A1@@;
~>            return publicKey.VerifyData(license, signature, hashAlgorithm, @@sample:R[S]AS[i]gn[a]tu[r]eP[a]dd[i]ng[.]Pk[c]s1@@);
        }

        public byte[] Hash(byte[] blob)
        {
~>            return CryptographicOperations.HashData(@@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]M[D]5@@, blob);
        }
    }
}
