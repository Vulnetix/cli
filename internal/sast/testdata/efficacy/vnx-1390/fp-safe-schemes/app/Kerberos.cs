using System.Net;

public class Kerberos
{
    public void Listen(HttpListener listener)
    {
        listener.AuthenticationSchemes = AuthenticationSchemes.Negotiate;
        var cache = new CredentialCache();
        cache.Add(uri, "Negotiate", CredentialCache.DefaultNetworkCredentials);
    }
}
