using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    public class DiagnosticsController : Controller
    {
        [HttpGet]
        public IActionResult Lookup()
        {
            string domain = Request.Query["domain"];
~>            var psi = new ProcessStartInfo("nslookup", domain)
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
            };
            using var p = Process.Start(psi);
            return Content(p.StandardOutput.ReadToEnd());
        }

        [HttpGet]
        public IActionResult Trace(string target)
        {
            var p = new Process();
            p.StartInfo.FileName = "traceroute";
~>            p.StartInfo.Arguments = target;
            p.StartInfo.UseShellExecute = false;
            p.Start();
            return Ok();
        }

        [HttpPost]
        public IActionResult Convert([FromForm] string name)
        {
            var output = name + ".pdf";
~>            Process.Start("libreoffice", "--headless --convert-to pdf " + output);
            return Ok();
        }
    }
}
