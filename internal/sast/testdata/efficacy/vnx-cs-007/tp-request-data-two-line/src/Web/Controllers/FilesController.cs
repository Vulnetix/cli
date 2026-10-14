using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    public class FilesController : Controller
    {
        private const string UploadDir = "/var/app/uploads";

        public IActionResult Get()
        {
            string filename = Request.Query["file"];
~>            string fullPath = Path.Combine(UploadDir, filename);
            return File(System.IO.File.ReadAllBytes(fullPath), "application/octet-stream");
        }

        public IActionResult Purge()
        {
~>            System.IO.File.Delete(Path.Combine(UploadDir, Request.Form["name"]));
            return Ok();
        }

        public IActionResult Preview()
        {
            var report = Request.Query["r"].ToString();
~>            var text = System.IO.File.ReadAllText($"{UploadDir}/{report}");
            return Content(text);
        }

        public IActionResult Stream()
        {
            var name = HttpContext.Request.Query["n"];
~>            var fs = new FileStream(UploadDir + "/" + name, FileMode.Open);
            return File(fs, "application/octet-stream");
        }

        public IActionResult Static()
        {
~>            var file = Path.Join("/srv/static", Request.Path.Value);
            return PhysicalFile(file, "text/html");
        }
    }
}
