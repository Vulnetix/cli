using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Shop.Services
{
    public class TokenProtector
    {
        public byte[] Protect(byte[] key, byte[] data)
        {
            using var aes = Aes.Create();
            aes.Key = key;
~>            aes.IV = new byte[16];
            using var enc = aes.CreateEncryptor();
            return enc.TransformFinalBlock(data, 0, data.Length);
        }

        public byte[] Protect2(byte[] key, byte[] data)
        {
            using var aes = Aes.Create();
~>            using var enc = aes.CreateEncryptor(key, @@sample:E[n]co[d]in[g][.]U[T]F8[.]Ge[t]By[t]es@@("1234567890abcdef"));
            return enc.TransformFinalBlock(data, 0, data.Length);
        }
    }
}
