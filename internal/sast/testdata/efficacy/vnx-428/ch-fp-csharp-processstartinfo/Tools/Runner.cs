using System.Diagnostics;

namespace Acme.Tools
{
    public static class Runner
    {
        public static void Run()
        {
            var psi = new ProcessStartInfo
            {
                FileName = @"C:\Program Files\Acme\worker.exe",
                Arguments = "--queue jobs",
                UseShellExecute = false,
            };
            Process.Start(psi);
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Acme", "InstallPath", @"C:\Program Files\Acme\worker.exe");
        }
    }
}
