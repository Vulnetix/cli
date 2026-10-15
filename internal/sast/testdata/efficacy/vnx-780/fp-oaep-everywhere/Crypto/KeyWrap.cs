using System.Security.Cryptography;

public static class KeyWrap
{
    public static byte[] Wrap(RSACryptoServiceProvider rsa, byte[] key) => rsa.Encrypt(key, true);
    public static byte[] Wrap2(RSA rsa, byte[] key) => rsa.Encrypt(key, @@sample:R[S]AE[n]cr[y]pt[i]on[P]ad[d]in[g][.]O[a]ep[S]HA[2]56@@);
    public static byte[] Sign(RSA rsa, byte[] d) => rsa.SignData(d, @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A2[5]6@@, @@sample:R[S]AS[i]gn[a]tu[r]eP[a]dd[i]ng[.]Pk[c]s1@@);
    public static byte[] Aes(Aes aes, byte[] d) => aes.EncryptCbc(d, new byte[16]);
}
