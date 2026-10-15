using Microsoft.AspNetCore.Mvc;

namespace Docs.Controllers;

public class FilesController : Controller
{
    private readonly string _root = "/srv/docs";

    [HttpGet("files/{name}")]
    public IActionResult Download(string name)
    {
~>        var path = Path.Combine(_root, name);
        return PhysicalFile(path, "application/octet-stream");
    }

    [HttpGet("files/raw")]
    public async Task<IActionResult> Raw([FromQuery] string relative)
    {
~>        var text = await System.IO.File.ReadAllTextAsync(
            _root + "/" + relative);
        return Content(text);
    }
}
