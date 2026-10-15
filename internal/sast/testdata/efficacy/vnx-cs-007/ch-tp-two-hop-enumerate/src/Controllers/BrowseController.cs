using Microsoft.AspNetCore.Mvc;

namespace Docs.Controllers;

public class BrowseController : Controller
{
    private readonly string _root = "/srv/share";

    [HttpGet]
    public IActionResult List()
    {
        var dir = Request.Query["dir"].ToString();
        var full = _root + "/" + dir;
~>        var files = Directory.EnumerateFiles(full).Select(Path.GetFileName);
        return Json(files);
    }

    [HttpPost]
    public IActionResult Note([FromForm] string body)
    {
        System.IO.File.WriteAllText(Path.Combine(_root, "notes.txt"), body);
        return Ok();
    }
}
