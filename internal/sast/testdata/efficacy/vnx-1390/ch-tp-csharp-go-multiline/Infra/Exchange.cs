using System;
using System.Net;

namespace Infra
{
    public static class Exchange
    {
        public static ICredentials For(string url, string user, string pass)
        {
            var cache = new CredentialCache();
            cache.Add(
                new Uri(url),
~>                "NTLM",
                new NetworkCredential(user, pass, "CORP"));
            return cache;
        }
    }
}
