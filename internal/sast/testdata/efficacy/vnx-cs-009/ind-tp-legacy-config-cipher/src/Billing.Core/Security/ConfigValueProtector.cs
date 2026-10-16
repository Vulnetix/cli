using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Billing.Core.Security
{
    internal static class ConfigValueProtector
    {
        public static byte[] Encrypt(byte[] key, byte[] iv, string plaintext)
        {
~>            using var tdes = TripleDES.Create();
            tdes.Key = key;
            tdes.IV = iv;
            tdes.Mode = CipherMode.CBC;

            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, tdes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                var data = Encoding.UTF8.GetBytes(plaintext);
                cs.Write(data, 0, data.Length);
            }
            return ms.ToArray();
        }

        public static string DecryptLegacy(byte[] key, byte[] iv, byte[] cipherText)
        {
~>            var des = new DESCryptoServiceProvider
            {
                Key = key,
                IV = iv,
                Padding = PaddingMode.PKCS7,
            };
            using var decryptor = des.CreateDecryptor();
            var plain = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
            return Encoding.UTF8.GetString(plain);
        }

        public static ICryptoTransform Rc2Transform(byte[] key, byte[] iv)
        {
~>            var rc2 = RC2.Create();
            return rc2.CreateEncryptor(key, iv);
        }
    }
}
