using System;
using System.Security.Cryptography;
using System.Text;

public static class Protector
{
~>    private static readonly byte[] Salt = Encoding.ASCII.GetBytes("pepper-2019-v1");

    public static byte[] DeriveKey(string password)
    {
        using (var kdf = new Rfc2898DeriveBytes(password, Salt, 10000))
        {
            return kdf.GetBytes(32);
        }
    }

    public static byte[] Derive2(string password)
    {
~>        return @@sample:R[f]c2[8]98[D]er[i]ve[B]yt[e]s[.][P]bk[d]f2@@(password, @@sample:E[n]co[d]in[g][.]U[T]F8[.]Ge[t]By[t]es@@("static"), 100000, @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A2[5]6@@, 32);
    }
}
