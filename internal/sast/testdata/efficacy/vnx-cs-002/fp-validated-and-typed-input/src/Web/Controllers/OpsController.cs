using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    public class OpsController : Controller
    {
        private static readonly string[] AllowedServices = { "web", "worker" };

        [HttpGet]
        public IActionResult Ping()
        {
            string host = Request.Query["host"];
            if (!Regex.IsMatch(host, "^[a-zA-Z0-9.-]+$"))
            {
                return BadRequest();
            }
            var psi = new ProcessStartInfo("ping", "-c 1 " + host);
            Process.Start(psi);
            return Ok();
        }

        [HttpPost]
        public IActionResult Restart(int id)
        {
            Process.Start("systemctl", "restart worker@" + id);
            return Ok();
        }

        [HttpPost]
        public IActionResult Reload(string service)
        {
            if (!AllowedServices.Contains(service))
            {
                return BadRequest();
            }
            Process.Start("systemctl", "reload " + service);
            return Ok();
        }
    }
}
