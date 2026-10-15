using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Ops.Controllers;

public class NetworkController : Controller
{
    [HttpGet]
    public IActionResult Ping()
    {
        var host = Request.Query["host"].ToString();
        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
~>            Arguments = "/c ping -n 1 " + host,
            RedirectStandardOutput = true,
        };
        using var proc = Process.Start(psi);
        return Content(proc!.StandardOutput.ReadToEnd());
    }
}
