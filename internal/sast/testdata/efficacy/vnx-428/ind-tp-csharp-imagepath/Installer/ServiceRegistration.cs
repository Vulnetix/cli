using Microsoft.Win32;

namespace Acme.Installer
{
    public static class ServiceRegistration
    {
        private const string ServiceKey = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcmeAgent";

        public static void RepairImagePath()
        {
~>            Registry.SetValue(ServiceKey, "ImagePath", "C:\\Program Files\\Acme Agent\\agent.exe --service");
        }
    }
}
