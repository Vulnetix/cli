using System.Management.Automation;
using System.Threading.Tasks;
using CliWrap;
using Microsoft.AspNetCore.Mvc;

namespace AdminTools.Controllers
{
    public class DirectoryController : Controller
    {
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Disable()
        {
            var samAccount = Request.Form["sam"];
            using var ps = PowerShell.Create();
~>            ps.AddScript("Disable-ADAccount -Identity " + samAccount);
            ps.Invoke();
            return RedirectToAction("Index");
        }

        public async Task<IActionResult> Archive(string folder)
        {
            var archiveName = folder + ".tar.gz";
~>            await Cli.Wrap("sh").WithArguments($"-c \"tar czf /backups/{archiveName} /data/{folder}\"").ExecuteAsync();
            return Ok();
        }
    }
}
