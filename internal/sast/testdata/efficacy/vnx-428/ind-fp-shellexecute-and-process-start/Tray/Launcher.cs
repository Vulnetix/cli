using System.Diagnostics;

namespace Acme.Tray
{
    public static class Launcher
    {
        public static void OpenConsole()
        {
            // CreateProcess(NULL, "C:\\Program Files\\Acme\\console.exe") would be unsafe
            Process.Start(@"C:\Program Files\Acme\console.exe", "--tray");
            var psi = new ProcessStartInfo
            {
                FileName = @"C:\Program Files\Acme\helper.exe",
                Arguments = "--quiet",
                UseShellExecute = false,
            };
            Process.Start(psi);
        }
    }
}
