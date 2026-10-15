using Microsoft.AspNetCore.Mvc;

namespace Docs.Controllers;

public class UploadController : Controller
{
    [HttpPost]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        var safeName = Path.GetFileName(file.FileName);
        var target = Path.Combine(_uploads, safeName);
        await using var stream = new FileStream(target, FileMode.Create);
        await file.CopyToAsync(stream);
        return Ok();
    }

    [HttpPost]
    public async Task<IActionResult> Store(IFormFile file)
    {
        var stored = Path.Combine(_uploads, Guid.NewGuid().ToString("N") + ".bin");
        await using var stream = System.IO.File.Create(stored);
        await file.CopyToAsync(stream);
        return Ok(new { name = file.FileName, size = file.Length });
    }
}
