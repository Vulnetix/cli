using System.Security.Cryptography;

public class Safe
{
    public byte[] Protect(byte[] key, byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        using var enc = aes.CreateEncryptor(aes.Key, aes.IV);
        return enc.TransformFinalBlock(data, 0, data.Length);
    }

    public byte[] Derive(string password, byte[] salt)
    {
        using var kdf = new Rfc2898DeriveBytes(password, salt, 210000, @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A2[5]6@@);
        return kdf.GetBytes(32);
    }

    public byte[] Derive2(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        using var kdf = new Rfc2898DeriveBytes(password, salt, 210000, @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]S[H]A2[5]6@@);
        return kdf.GetBytes(32);
    }

    public byte[] Fill()
    {
        var iv = new byte[16];
        RandomNumberGenerator.Fill(iv);
        using var aes = Aes.Create();
        aes.IV = iv;
        return aes.IV;
    }
}
