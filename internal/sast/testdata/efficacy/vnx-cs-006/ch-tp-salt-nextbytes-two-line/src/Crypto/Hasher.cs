using System.Security.Cryptography;

namespace App.Crypto;

public static class Hasher
{
    public static (byte[] Hash, byte[] Salt) Hash(string password)
    {
        byte[] salt = new byte[16];
~>        new Random().NextBytes(salt);
        using var kdf = new Rfc2898DeriveBytes(password, salt, 100_000, @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A2[5]6@@);
        return (kdf.GetBytes(32), salt);
    }

    public static byte[] NewIv()
    {
        var iv = new byte[16];
        var r = new System.Random();
~>        r.NextBytes(iv);
        return iv;
    }
}
