using System.IO;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

public class UploadController : Controller
{
    private readonly IWebHostEnvironment _env;

    [HttpPost]
    public async Task<IActionResult> Upload(IFormFile file)
    {
~>        var path = Path.Combine(_env.WebRootPath, "uploads", file.FileName);
        using (var stream = new FileStream(path, FileMode.Create))
        {
            await file.CopyToAsync(stream);
        }
        return Ok();
    }

    public void Legacy(HttpPostedFileBase upload)
    {
        var name = Path.GetFileName(upload.FileName);
~>        upload.SaveAs(Server.MapPath("~/App_Data/" + name));
    }
}
