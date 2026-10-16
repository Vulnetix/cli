using System;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Storage.Api.Hashing
{
    public enum DigestKind
    {
        MD5,
        SHA1,
        SHA256,
    }

    public sealed class ChecksumPolicy
    {
        private readonly ILogger<ChecksumPolicy> _log;

        public ChecksumPolicy(ILogger<ChecksumPolicy> log) => _log = log;

        public DigestKind Default { get; set; } = DigestKind.SHA256;

        public HashAlgorithmName Resolve(DigestKind kind)
        {
            switch (kind)
            {
                case DigestKind.MD5:
                case DigestKind.SHA1:
                    _log.LogWarning("Rejecting legacy digest {Kind}; MD5.Create() and SHA1.Create() are no longer allowed", kind);
                    throw new NotSupportedException($"Digest {kind} is not permitted.");
                default:
                    return HashAlgorithmName.SHA256;
            }
        }

        public static void EnsureStrong(HashAlgorithmName requested)
        {
            if (requested == HashAlgorithmName.SHA1 || requested == HashAlgorithmName.MD5)
            {
                throw new CryptographicException("Weak hash algorithms are rejected.");
            }
        }

        public static byte[] Compute(byte[] data)
        {
            // Previously: using var md5 = MD5.Create(); return md5.ComputeHash(data);
            using var sha = SHA256.Create();
            return sha.ComputeHash(data);
        }
    }
}
