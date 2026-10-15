using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Setup
{
    public static class AclInstaller
    {
        public static void Grant(string dir)
        {
            var info = new DirectoryInfo(dir);
            DirectorySecurity security = info.GetAccessControl();
            var world = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
~>            security.AddAccessRule(new FileSystemAccessRule(world, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            info.SetAccessControl(security);
        }
    }
}
