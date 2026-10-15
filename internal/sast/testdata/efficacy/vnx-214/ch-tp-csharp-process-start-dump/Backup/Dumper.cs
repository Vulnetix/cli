using System.Diagnostics;

namespace Backup
{
    public static class Dumper
    {
        public static void Run(string user, string password, string db)
        {
~>            var p = Process.Start("mysqldump", $"-u {user} -p{password} {db}");
            p.WaitForExit();
        }
    }
}
