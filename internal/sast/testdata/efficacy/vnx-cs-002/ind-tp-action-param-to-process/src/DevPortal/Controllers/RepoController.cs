using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace DevPortal.Controllers
{
    public class RepoController : Controller
    {
        [HttpPost]
        public IActionResult Clone(string repositoryUrl, string branch)
        {
~>            var proc = Process.Start("git", "clone --branch " + branch + " " + repositoryUrl + " /srv/checkouts/latest");
            proc.WaitForExit();
            return RedirectToAction("Index");
        }

        [HttpGet]
        public IActionResult Lookup()
        {
            string domain = Request.Query["domain"];
            var psi = new ProcessStartInfo
            {
                FileName = "nslookup",
~>                Arguments = domain,
                RedirectStandardOutput = true,
                UseShellExecute = false,
            };
            using var p = Process.Start(psi);
            return Content(p.StandardOutput.ReadToEnd());
        }
    }
}
