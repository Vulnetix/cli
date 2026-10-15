using System.Security.Cryptography;

public static class Crypto
{
    public static byte[] Open(RSACryptoServiceProvider rsa, byte[] data)
    {
~>        return rsa.Decrypt(data, false);
    }
}
