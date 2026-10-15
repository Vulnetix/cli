using System;
using System.Net;

public class ShareClient
{
    public HttpWebRequest Build(Uri uri, NetworkCredential cred)
    {
        var cache = new CredentialCache();
~>        cache.Add(uri, "NTLM", cred);
~>        cache.Add(uri, "Digest", cred);
        var req = (HttpWebRequest)WebRequest.Create(uri);
        req.Credentials = cache;
        return req;
    }

    public void Listen(HttpListener listener)
    {
~>        listener.AuthenticationSchemes = AuthenticationSchemes.Ntlm;
    }
}
