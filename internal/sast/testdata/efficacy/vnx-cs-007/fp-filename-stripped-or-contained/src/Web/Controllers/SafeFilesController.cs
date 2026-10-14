using System;
using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    public class SafeFilesController : Controller
    {
        private readonly string _root = Path.GetFullPath("/srv/files");

        [HttpPost]
        public IActionResult Upload(IFormFile file)
        {
            var dest = Path.Combine(_root, Path.GetFileName(file.FileName));
            using var stream = new FileStream(dest, FileMode.Create);
            file.CopyTo(stream);
            return Ok();
        }

        public IActionResult Read()
        {
            var safe = Path.GetFileName(Request.Query["f"]);
            return PhysicalFile(Path.Combine(_root, safe), "text/plain");
        }

        public IActionResult Contained(string name)
        {
            var full = Path.GetFullPath(Path.Combine(_root, name));
            if (!full.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            {
                return BadRequest();
            }
            return PhysicalFile(full, "text/plain");
        }

        public IActionResult Invoice(Guid id, int page)
        {
            var path = Path.Combine(_root, id + ".pdf");
            var thumb = Path.Combine(_root, "thumbs", page.ToString());
            return PhysicalFile(path, "application/pdf");
        }

        public IActionResult Checked(string report)
        {
            if (!Regex.IsMatch(report, "^[a-z0-9-]+$"))
            {
                return BadRequest();
            }
            return PhysicalFile(Path.Combine(_root, report + ".pdf"), "application/pdf");
        }
    }
}
