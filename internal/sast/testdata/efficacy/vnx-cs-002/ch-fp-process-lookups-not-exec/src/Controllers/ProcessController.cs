using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Ops.Controllers;

public class ProcessController : Controller
{
    [HttpGet]
    public IActionResult Find(string name)
    {
        var found = Process.GetProcessesByName(name);
        return Json(found.Select(p => p.Id));
    }

    [HttpGet]
    public IActionResult Kill(int pid)
    {
        Process.GetProcessById(pid).Kill();
        return Ok();
    }

    [HttpGet]
    public IActionResult Describe(string command)
    {
        ViewData["Arguments"] = "Requested: " + command;
        return View();
    }
}
