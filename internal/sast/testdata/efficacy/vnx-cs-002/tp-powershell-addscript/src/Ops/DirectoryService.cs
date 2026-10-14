using System.Collections.ObjectModel;
using System.Management.Automation;

namespace Ops
{
    public class DirectoryService
    {
        public Collection<PSObject> FindUser(string user)
        {
            using var ps = PowerShell.Create();
~>            ps.AddScript("Get-ADUser -Identity " + user);
            return ps.Invoke();
        }

        public Collection<PSObject> Disable(string account)
        {
            using var ps = PowerShell.Create();
            var script = $"Disable-ADAccount -Identity '{account}'";
~>            ps.AddScript(script);
            return ps.Invoke();
        }
    }
}
