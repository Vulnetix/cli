using System.Net;

public class Mailer
{
    public void Send(MailMessage msg)
    {
        var client = new SmtpClient("smtp.example.org");
~>        client.Credentials = new NetworkCredential("mailer", "Sm7p!Passw0rd");
        client.Send(msg);
    }
}
