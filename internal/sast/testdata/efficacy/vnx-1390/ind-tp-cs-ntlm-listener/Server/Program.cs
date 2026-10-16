using System.Net;

class Program {
    static void Main() {
        var listener = new HttpListener();
~>      listener.AuthenticationSchemes = AuthenticationSchemes.Ntlm;
        listener.Prefixes.Add("http://+:8080/");
        listener.Start();
    }
}
