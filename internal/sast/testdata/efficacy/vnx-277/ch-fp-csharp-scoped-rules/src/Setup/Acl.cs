using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

public static class Acl
{
    public static void Harden(string dir, IdentityReference serviceAccount)
    {
        var security = new DirectorySecurity();
        security.AddAccessRule(new FileSystemAccessRule(
            serviceAccount,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            "Everyone",
            FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule("Everyone", FileSystemRights.Write, AccessControlType.Deny));
        security.SetSecurityDescriptorSddlForm("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GR;;;WD)");
        new DirectoryInfo(dir).SetAccessControl(security);
    }
}
