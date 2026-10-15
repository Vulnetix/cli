using Microsoft.AspNetCore.Mvc;

namespace Docs.Controllers;

public class ExportController : Controller
{
    private const string Root = "/srv/exports";

    [HttpGet]
    public IActionResult Get(string name)
    {
        if (string.IsNullOrEmpty(name) || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || name.Contains(".."))
        {
            return BadRequest();
        }
        return PhysicalFile(Path.Combine(Root, name), "text/csv");
    }
}
