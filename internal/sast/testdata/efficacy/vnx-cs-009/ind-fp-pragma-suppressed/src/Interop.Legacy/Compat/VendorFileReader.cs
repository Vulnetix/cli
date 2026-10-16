using System.IO;
using System.Security.Cryptography;

namespace Interop.Legacy.Compat
{
    public static class VendorFileReader
    {
        // The vendor's export format is fixed: files are DES-CBC with a shared key
        // and carry an MD5 trailer. Approved under SEC-EXC-118 until the vendor upgrades.
#pragma warning disable CA5351
        public static byte[] ComputeTrailer(Stream payload)
        {
            using var md5 = MD5.Create();
            return md5.ComputeHash(payload);
        }

        public static Stream OpenDecrypted(Stream encrypted, byte[] key, byte[] iv)
        {
            var des = DES.Create();
            return new CryptoStream(encrypted, des.CreateDecryptor(key, iv), CryptoStreamMode.Read);
        }
#pragma warning restore CA5351
    }
}
