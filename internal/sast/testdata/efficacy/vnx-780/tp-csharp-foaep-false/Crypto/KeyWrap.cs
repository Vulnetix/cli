using System.Security.Cryptography;

public static class KeyWrap
{
    public static byte[] Wrap(RSACryptoServiceProvider rsa, byte[] key)
    {
~>        return rsa.Encrypt(key, false);
    }

    public static byte[] Unwrap(RSA rsa, byte[] blob)
    {
~>        return rsa.Decrypt(blob, @@sample:R[S]AE[n]cr[y]pt[i]on[P]ad[d]in[g][.]P[k]cs[1]@@);
    }
}
