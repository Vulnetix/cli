using Microsoft.AspNetCore.Mvc;

namespace Docs.Controllers;

public class UploadController : Controller
{
    [HttpPost]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        var uploads = Path.Combine(_env.WebRootPath, "uploads");
~>        await using var stream = new FileStream(Path.Combine(uploads, file.FileName), FileMode.Create);
        await file.CopyToAsync(stream);
        return Ok();
    }
}
