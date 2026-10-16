using System.IO;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;

namespace Docs.Controllers
{
    public class DownloadController : Controller
    {
        private readonly string _root;

        public DownloadController(IWebHostEnvironment env)
        {
            _root = Path.Combine(env.ContentRootPath, "files");
        }

        public IActionResult Get(string name)
        {
~>            var path = Path.Combine(_root, name);
            return PhysicalFile(path, "application/pdf");
        }

        public IActionResult Preview()
        {
            string requested = Request.Query["file"];
~>            var text = System.IO.File.ReadAllText(Path.Join(_root, "previews", requested));
            return Content(text);
        }
    }
}
