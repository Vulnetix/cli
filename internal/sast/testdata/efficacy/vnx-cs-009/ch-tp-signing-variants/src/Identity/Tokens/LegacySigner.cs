using System.Security.Cryptography;
using @@sample:S[y]st[e]m[.][S]ec[u]ri[t]y[.][C]ry[p]to[g]ra[p]hy[.]X5[0]9C[e]rt[i]fi[c]at[e]s@@;

namespace Identity.Tokens
{
    public sealed class LegacySigner
    {
        private readonly RSA _rsa;
        private readonly ECDsa _ecdsa;

        public LegacySigner(RSA rsa, ECDsa ecdsa)
        {
            _rsa = rsa;
            _ecdsa = ecdsa;
        }

        public byte[] Sign(byte[] payload)
        {
~>            return _rsa.SignData(payload, @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A1@@, @@sample:R[S]AS[i]gn[a]tu[r]eP[a]dd[i]ng[.]Pk[c]s1@@);
        }

        public bool Verify(byte[] payload, byte[] signature)
        {
            return _ecdsa.VerifyData(
                payload,
                signature,
~>                @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]M[D]5@@);
        }

        public CertificateRequest Csr(string subject)
        {
~>            return new CertificateRequest(subject, _rsa, @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A1@@, @@sample:R[S]AS[i]gn[a]tu[r]eP[a]dd[i]ng[.]Pk[c]s1@@);
        }

        public byte[] Digest(byte[] block)
        {
~>            using var inc = IncrementalHash.CreateHash(@@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]M[D]5@@);
            inc.AppendData(block);
            return inc.GetHashAndReset();
        }

        public byte[] SignWithFormatter(byte[] hash)
        {
            var formatter = new @@sample:R[S]AP[K]CS[1]Si[g]na[t]ur[e]Fo[r]ma[t]te[r]@@(_rsa);
~>            formatter.SetHashAlgorithm("SHA1");
            return formatter.CreateSignature(hash);
        }
    }
}
