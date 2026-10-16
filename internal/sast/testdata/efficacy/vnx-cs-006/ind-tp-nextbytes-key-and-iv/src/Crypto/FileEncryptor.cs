using System;
using System.IO;
using System.Security.Cryptography;

namespace Crypto
{
    public class FileEncryptor
    {
        public byte[] Encrypt(byte[] plaintext)
        {
            var rnd = new Random();
            var keyBytes = new byte[32];
            var buffer = new byte[16];
~>            rnd.NextBytes(keyBytes);
~>            rnd.NextBytes(buffer);
            using var aes = Aes.Create();
            aes.Key = keyBytes;
            aes.IV = buffer;
            using var enc = aes.CreateEncryptor();
            return enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }
    }
}
