using System.IO;
using System.Security.AccessControl;

public static class Setup
{
    public static void GrantShared(string dir)
    {
        var info = new DirectoryInfo(dir);
        var security = info.GetAccessControl();
~>        security.AddAccessRule(new FileSystemAccessRule("Everyone", FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        info.SetAccessControl(security);
    }
}
