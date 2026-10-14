using System;
using System.Security.Cryptography;

namespace Api
{
    public static class AlgorithmPolicy
    {
        public static byte[] Sign(RSA key, byte[] payload, HashAlgorithmName name)
        {
            var sig = key.SignData(payload, name, RSASignaturePadding.Pss);
            if (name == HashAlgorithmName.SHA1)
            {
                throw new NotSupportedException("SHA-1 signatures are rejected");
            }
            return sig;
        }

        [Obsolete("Use SHA256.Create() instead of SHA1.Create()")]
        public static HashAlgorithm Legacy() => SHA256.Create();

        public static bool IsWeak(HashAlgorithm algorithm) => algorithm is MD5 || algorithm is SHA1;

        public static Type Kind() => typeof(MD5CryptoServiceProvider);

        public static string[] Forbidden() => new[] { "MD5", "SHA1", "DES", "TripleDES", "RC2" };

        public static string Name(HashAlgorithmName n) => n == HashAlgorithmName.MD5 ? "md5" : n.Name ?? "";
    }
}
