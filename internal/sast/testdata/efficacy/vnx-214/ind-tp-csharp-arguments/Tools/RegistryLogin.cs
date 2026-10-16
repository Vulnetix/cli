using System.Diagnostics;

namespace Deploy.Tools
{
    public static class RegistryLogin
    {
        public static void Login(string server, string user, string password)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "helm",
~>                Arguments = $"registry login {server} --username {user} --password={password}",
                UseShellExecute = false,
            };
            using var p = Process.Start(psi);
            p.WaitForExit();
        }
    }
}
