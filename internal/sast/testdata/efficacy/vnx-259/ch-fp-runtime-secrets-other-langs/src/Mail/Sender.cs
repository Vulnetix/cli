using System;
using System.Net;

public class Sender
{
    public NetworkCredential Credentials(string user) =>
        new NetworkCredential(user, Environment.GetEnvironmentVariable("SMTP_PASSWORD"));
}
