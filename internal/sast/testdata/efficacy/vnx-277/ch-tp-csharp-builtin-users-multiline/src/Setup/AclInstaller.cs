using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

public static class AclInstaller
{
    public static void OpenUp(string dir)
    {
        var info = new DirectoryInfo(dir);
        DirectorySecurity security = info.GetAccessControl();
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
~>        security.AddAccessRule(new FileSystemAccessRule(
            users,
            FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        info.SetAccessControl(security);
    }

    public static void OpenSddl(string dir)
    {
        var security = new DirectorySecurity();
~>        security.SetSecurityDescriptorSddlForm("D:PAI(A;OICI;FA;;;WD)");
        new DirectoryInfo(dir).SetAccessControl(security);
    }
}
