using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Diagnostics
{
    /// <summary>
    /// Flags legacy primitives. Never call MD5.Create() or new SHA1Managed() here.
    /// </summary>
    public static class CryptoAudit
    {
        private static readonly HashSet<Type> Banned = new()
        {
            typeof(@@sample:M[D]5C[r]yp[t]oS[e]rv[i]ce[P]ro[v]id[e]r@@),
            typeof(SHA1Managed),
            typeof(DESCryptoServiceProvider),
        };

        public static string Explain(string algo)
        {
            // MD5.HashData(...) is broken; DES.Create() too.
            return $"Algorithm {algo} is not allowed; replace \"MD5.Create()\" with SHA256.Create()";
        }

        public static bool IsBanned(object instance) => Banned.Contains(instance.GetType());

        public static string Name(HashAlgorithmName n) => n == @@sample:H[a]sh[A]lg[o]ri[t]hm[N]am[e][.]M[D]5@@ ? "md5" : n.Name;

        public static int Md5Length => 16;

        public static string MyMD5Helper(string s) => s;

        public static void Log(string message)
        {
            Console.WriteLine("Rejected SHA1.Create(): " + message);
        }
    }
}
