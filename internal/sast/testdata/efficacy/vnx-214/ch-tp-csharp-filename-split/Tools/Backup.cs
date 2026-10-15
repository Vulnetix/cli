using System.Diagnostics;

namespace Ops.Tools
{
    public static class Backup
    {
        public static void Run(string user, string password, string db)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "mysqldump",
~>                Arguments = $"-u{user} -p{password} {db}",
                RedirectStandardOutput = true,
            };
            Process.Start(psi);
        }
    }
}
