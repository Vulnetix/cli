using System.Net;
using System.Net.Mail;

namespace Acme.Mail
{
    public class Mailer
    {
        public SmtpClient Create()
        {
            var client = new SmtpClient("smtp.example.org", 587);
~>            client.Credentials = new NetworkCredential("svc-mailer", "Svc-Acct-2021");
            client.EnableSsl = true;
            return client;
        }
    }
}
