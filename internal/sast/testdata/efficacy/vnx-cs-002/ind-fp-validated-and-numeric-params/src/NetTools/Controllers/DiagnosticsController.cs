using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

namespace NetTools.Controllers
{
    public class DiagnosticsController : Controller
    {
        private static readonly Regex HostPattern = new Regex("^[a-zA-Z0-9.-]{1,253}$");

        public IActionResult Ping(string host)
        {
            if (!Regex.IsMatch(host, "^[a-zA-Z0-9.-]{1,253}$"))
            {
                return BadRequest();
            }
            var p = Process.Start("ping", "-c 4 " + host);
            p.WaitForExit();
            return Ok();
        }

        public IActionResult Stop(int pid)
        {
            Process.Start("kill", "-TERM " + pid);
            return Ok();
        }

        public IActionResult Port(string port)
        {
            if (!int.TryParse(port, out var number))
            {
                return BadRequest();
            }
            Process.Start("ss", "-tlnp sport = :" + number);
            return Ok();
        }
    }
}
