using System.Net;

class Program {
    static void Main() {
        var listener = new HttpListener();
        listener.AuthenticationSchemes = AuthenticationSchemes.Negotiate;
        // AuthenticationSchemes.Ntlm is disabled on purpose
    }
}
