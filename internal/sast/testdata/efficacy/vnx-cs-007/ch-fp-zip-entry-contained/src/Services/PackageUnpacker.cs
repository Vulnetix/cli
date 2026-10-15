using System;
using System.IO;
using System.IO.Compression;

namespace Portal.Services
{
    public class PackageUnpacker
    {
        public void Unpack(Stream upload, string destination)
        {
            var root = Path.GetFullPath(destination + Path.DirectorySeparatorChar);
            using var zip = new ZipArchive(upload);
            foreach (var entry in zip.Entries)
            {
                var target = Path.GetFullPath(Path.Combine(root, entry.FullName));
                if (!target.StartsWith(root, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("Entry escapes the destination");
                }
                entry.ExtractToFile(target, overwrite: true);
            }
        }

        public void UnpackFlat(Stream upload, string destination)
        {
            using var zip = new ZipArchive(upload);
            foreach (var entry in zip.Entries)
            {
                entry.ExtractToFile(Path.Combine(destination, Path.GetFileName(entry.FullName)));
            }
        }
    }
}
