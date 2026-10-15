using System.Diagnostics;

namespace Acme.Setup
{
    public static class ServiceSetup
    {
        public static void Install()
        {
~>            Process.Start("sc.exe", @"create AcmeSync binPath= C:\Program Files\Acme Sync\sync.exe start= auto");
~>            var psi = new ProcessStartInfo("sc", "config AcmeSync binpath= \"C:\\Program Files\\Acme Sync\\sync.exe --svc\"");
            Process.Start(psi);
        }
    }
}
