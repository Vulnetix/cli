using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Ops.Controllers;

[Route("tools")]
public class ToolsController : Controller
{
    [HttpPost("archive")]
    public IActionResult Archive(string folder)
    {
~>        var proc = Process.Start("/bin/bash", $"-c \"tar czf /tmp/out.tgz {folder}\"");
        proc.WaitForExit();
        return Ok();
    }

    [HttpPost("lookup")]
    public IActionResult Lookup([FromForm] string domain)
    {
~>        Process.Start(
            "sh",
            "-c \"nslookup " + domain + "\"");
        return Ok();
    }
}
