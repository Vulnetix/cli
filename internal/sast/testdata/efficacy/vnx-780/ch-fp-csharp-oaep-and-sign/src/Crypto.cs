using System.Security.Cryptography;

public static class Crypto
{
    public static byte[] Seal(RSA rsa, byte[] data)
    {
        return rsa.Encrypt(data, @@sample:R[S]AE[n]cr[y]pt[i]on[P]ad[d]in[g][.]O[a]ep[S]HA[2]56@@);
    }

    public static byte[] Sign(RSA rsa, byte[] data)
    {
        return rsa.SignData(data, @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A2[5]6@@, @@sample:R[S]AS[i]gn[a]tu[r]eP[a]dd[i]ng[.]Pk[c]s1@@);
    }

    public static byte[] Legacy(RSACryptoServiceProvider rsa, byte[] data)
    {
        return rsa.Encrypt(data, true);
    }
}
