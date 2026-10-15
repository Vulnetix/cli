using System.Diagnostics;

public class DbProvider
{
    public void Recreate(string uid, string pwd, string db)
    {
~>        string args = string.Format("--user={0} --password={1} --database={2}", uid, pwd, db);
        Process.Start("mysql", args);
    }

    public void Push(string token)
    {
        var psi = new ProcessStartInfo("registryctl");
~>        psi.Arguments = $"login --token {token}";
        Process.Start(psi);
    }
}
