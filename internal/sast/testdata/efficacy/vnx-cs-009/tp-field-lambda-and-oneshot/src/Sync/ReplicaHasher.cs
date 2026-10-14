using System;
using System.Security.Cryptography;

namespace Replication.Sync
{
    public sealed class ReplicaHasher
    {
~>        private static readonly MD5 Hasher = MD5.Create();

~>        private readonly Func<HashAlgorithm> _factory = () => SHA1.Create();

        public byte[] Hash(byte[] block)
        {
~>            using (MD5 md5 = MD5.Create())
            {
                return md5.ComputeHash(block);
            }
        }

        public byte[] OneShot(byte[] block)
        {
~>            return CryptographicOperations.HashData(HashAlgorithmName.MD5, block);
        }

        public byte[] Sign(ECDsa key, byte[] block)
        {
~>            return key.SignData(block, HashAlgorithmName.SHA1);
        }

        public HashAlgorithm Cast()
        {
~>            return (HashAlgorithm)new SHA1CryptoServiceProvider();
        }

        public byte[] Split(byte[] block)
        {
~>            using var h = MD5
                .Create();
            return h.ComputeHash(block);
        }

        public bool TryHash(ReadOnlySpan<byte> src, Span<byte> dst)
        {
~>            return SHA1.TryHashData(src, dst, out _);
        }
    }
}
