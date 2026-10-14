using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

public static class Setup
{
    public static void ShareData(string path)
    {
        var info = new DirectoryInfo(path);
        DirectorySecurity security = info.GetAccessControl();
~>        security.AddAccessRule(new FileSystemAccessRule("Everyone", FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(security);
    }

    public static void SharePlugins(string path)
    {
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        var info = new DirectoryInfo(path);
        var security = info.GetAccessControl();
~>        security.AddAccessRule(new FileSystemAccessRule(
            everyone,
            FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        info.SetAccessControl(security);
    }
}
