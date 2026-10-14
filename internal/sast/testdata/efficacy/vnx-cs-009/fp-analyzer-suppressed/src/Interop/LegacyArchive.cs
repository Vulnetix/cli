using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Archive.Interop
{
    public static class LegacyArchive
    {
        // The v1 archive format stores an MD5 of each entry; reading it needs MD5.
#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms
        public static byte[] EntryChecksum(byte[] entry)
        {
            using var md5 = MD5.Create();
            return md5.ComputeHash(entry);
        }
#pragma warning restore CA5351

        [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "v1 manifest format")]
        public static byte[] ManifestId(byte[] manifest)
        {
            return SHA1.HashData(manifest);
        }
    }
}
