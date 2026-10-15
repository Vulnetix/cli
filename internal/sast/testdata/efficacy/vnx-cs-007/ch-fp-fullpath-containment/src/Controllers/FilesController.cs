using Microsoft.AspNetCore.Mvc;

namespace Docs.Controllers;

public class FilesController : Controller
{
    private const string Root = "/srv/docs/";

    [HttpGet("files/{name}")]
    public IActionResult Download(string name)
    {
        var full = Path.GetFullPath(Path.Combine(Root, name));
        if (!full.StartsWith(Root, StringComparison.Ordinal))
        {
            return BadRequest();
        }
        return PhysicalFile(full, "application/octet-stream");
    }
}
