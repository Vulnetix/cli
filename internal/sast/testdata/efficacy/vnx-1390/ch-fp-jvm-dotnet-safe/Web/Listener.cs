using System.Net;

namespace Web
{
    public class Listener
    {
        public void Start()
        {
            var l = new HttpListener();
            l.AuthenticationSchemes = AuthenticationSchemes.Negotiate;
            // l.AuthenticationSchemes = AuthenticationSchemes.Ntlm;
            var cache = new CredentialCache();
            cache.Add(new System.Uri("https://api.example.com"), "Basic", new NetworkCredential("svc", "x"));
            l.Start();
        }
    }
}
