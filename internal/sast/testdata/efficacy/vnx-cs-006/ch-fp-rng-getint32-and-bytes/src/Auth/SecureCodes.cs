using System.Security.Cryptography;

namespace App.Auth;

public static class SecureCodes
{
    public static string Otp() => @@sample:R[a]nd[o]mN[u]mb[e]rG[e]ne[r]at[o]r[.][G]et[I]nt[3]2@@(100000, 1000000).ToString();

    public static string Token() => @@sample:C[o]nv[e]rt[.]To[B]as[e]64[S]tr[i]ng@@(RandomNumberGenerator.GetBytes(32));

    public static byte[] Salt()
    {
        var salt = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);
        return salt;
    }
}
