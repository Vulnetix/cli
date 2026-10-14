namespace Acme.Web;

public static class Seed
{
~>    public const string DefaultPassword = "Adm1n@Acme!";
    public static void Configure(Options o)
    {
~>        o.Smtp.Password = "Relay#2024pw";
    }
}
