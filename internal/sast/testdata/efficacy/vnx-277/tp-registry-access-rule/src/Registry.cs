using Microsoft.Win32;
using System.Security.AccessControl;

public static class RegistrySetup
{
    public static void Open(RegistryKey key)
    {
        var security = key.GetAccessControl();
~>        security.AddAccessRule(new RegistryAccessRule("Users", RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
        key.SetAccessControl(security);
    }
}
