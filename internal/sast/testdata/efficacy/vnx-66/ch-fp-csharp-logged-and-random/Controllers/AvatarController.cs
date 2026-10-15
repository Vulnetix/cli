using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

public class AvatarController : Controller
{
    private readonly ILogger<AvatarController> _logger;

    public AvatarController(ILogger<AvatarController> logger) => _logger = logger;

    [HttpPost]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        _logger.LogInformation("Upload {Name} ({Length} bytes)", file.FileName, file.Length);
        var target = Path.Combine("/srv/avatars", Path.GetRandomFileName());
        using var stream = System.IO.File.Create(target);
        await file.CopyToAsync(stream);
        return Ok(new { name = file.FileName });
    }
}
