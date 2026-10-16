using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

public static class Setup
{
    public static void Grant(string dir, SecurityIdentifier serviceAccountSid)
    {
        var info = new DirectoryInfo(dir);
        var security = info.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(serviceAccountSid, FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule("Everyone", FileSystemRights.ReadAndExecute,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule("Users", FileSystemRights.Write,
            InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Deny));
        info.SetAccessControl(security);
    }
}
