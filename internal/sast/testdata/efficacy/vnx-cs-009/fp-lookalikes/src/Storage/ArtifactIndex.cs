using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Registry.Storage
{
    public enum DigestKind
    {
        MD5,
        SHA1,
        SHA256,
    }

    public sealed class Artifact
    {
        public string Name { get; set; } = "";
        public string MD5 { get; set; } = "";
        public string SHA1 { get; set; } = "";
        public string Sha1Hash { get; set; } = "";
        public DigestKind Kind { get; set; } = DigestKind.SHA256;
    }

    public sealed class ArtifactIndex
    {
        private const string DESCRIPTION = "Index of uploaded artifacts";

        public IEnumerable<Artifact> Newest(IEnumerable<Artifact> all) =>
            all.OrderByDescending(a => a.Name);

        public bool IsLegacy(Artifact a) => a.Kind == DigestKind.MD5 || a.Kind == DigestKind.SHA1;

        public string Label(Artifact a) => a.Kind == DigestKind.MD5 ? nameof(DigestKind.MD5) : "SHA1";

        public void Reject(HashAlgorithmName name)
        {
            if (name == HashAlgorithmName.SHA1 || name == HashAlgorithmName.MD5)
            {
                throw new CryptographicException("SHA1 and MD5 are not accepted");
            }
        }

        public string ComputeSha1Checksum(Artifact a) => a.SHA1;

        public static string Describe() => DESCRIPTION;
    }
}
