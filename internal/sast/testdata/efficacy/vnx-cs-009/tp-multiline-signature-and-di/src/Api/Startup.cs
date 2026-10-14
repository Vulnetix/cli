using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;

namespace Api
{
    public static class Startup
    {
        public static void Register(IServiceCollection services)
        {
~>            services.AddSingleton<HashAlgorithm>(_ => MD5.Create());
~>            services.AddTransient<SymmetricAlgorithm>(_ => TripleDES.Create());
        }

        public static byte[] Sign(RSA key, byte[] header, byte[] body)
        {
            var payload = Concat(header, body);
            return key.SignData(
                payload,
                0,
                payload.Length,
~>                HashAlgorithmName.MD5,
                RSASignaturePadding.Pkcs1);
        }

        public static bool Check(ECDsa key, byte[] data, byte[] sig) =>
~>            key.VerifyData(data, sig, HashAlgorithmName.SHA1);

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            a.CopyTo(r, 0);
            b.CopyTo(r, a.Length);
            return r;
        }
    }
}
