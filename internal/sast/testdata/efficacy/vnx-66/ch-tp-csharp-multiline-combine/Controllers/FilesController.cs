using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

public class FilesController : Controller
{
    private readonly IWebHostEnvironment _env;

    public FilesController(IWebHostEnvironment env) => _env = env;

    [HttpPost]
    public async Task<IActionResult> Upload(IFormFile formFile)
    {
~>        var path = Path.Combine(_env.WebRootPath, "uploads", formFile.FileName);
        using (var stream = System.IO.File.Create(path))
        {
            await formFile.CopyToAsync(stream);
        }
        return Ok();
    }
}
