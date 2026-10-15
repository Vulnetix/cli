using System.Diagnostics;
using Microsoft.Win32;

namespace Acme.Installer
{
    public static class SafeRegistration
    {
        public static void Register(RegistryKey key)
        {
            key.SetValue("ImagePath", "\"C:\\Program Files\\Acme\\svc.exe\"");
            key.SetValue("ImagePath", @"""C:\Program Files\Acme\svc.exe"" -k");
            key.SetValue("Description", @"C:\Program Files\Acme\svc.exe");
            key.SetValue("ImagePath", @"C:\Acme\svc.exe");
            Process.Start(@"C:\Program Files\Acme\tray.exe");
            Process.Start("sc.exe", "create AcmeTray binPath= \"\\\"C:\\Program Files\\Acme\\tray.exe\\\"\"");
            // key.SetValue("ImagePath", @"C:\Program Files\Acme\svc.exe");
            Console.WriteLine("CreateProcess(NULL, \"C:\\Program Files\\x.exe\") is unsafe");
        }
    }
}
