using System.Diagnostics;
using Microsoft.Win32;

namespace Acme.Installer
{
    public static class ServiceRegistration
    {
        public static void Register()
        {
            using var key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\AcmeSvc");
~>            key.SetValue("ImagePath", @"C:\Program Files\Acme\svc.exe");
~>            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcmeAgent", "ImagePath", "C:\\Program Files\\Acme\\agent.exe -k");
~>            Process.Start("sc.exe", "create AcmeTray binPath= \"C:\\Program Files\\Acme\\tray.exe\" start= auto");
        }
    }
}
