using System;
using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace Docs.Controllers
{
    public class FilesController : Controller
    {
        private static readonly string BaseDir = Path.GetFullPath("/var/app/files");

        public IActionResult Get(string name)
        {
            var safeName = Path.GetFileName(name);
            var path = Path.Combine(BaseDir, safeName);
            return PhysicalFile(path, "application/octet-stream");
        }

        public IActionResult Nested()
        {
            string userPath = Request.Query["path"];
            string requested = Path.Combine(BaseDir, userPath);
            string canonical = Path.GetFullPath(requested);
            if (!canonical.StartsWith(BaseDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                return Forbid();
            }
            return PhysicalFile(canonical, "application/octet-stream");
        }
    }
}
