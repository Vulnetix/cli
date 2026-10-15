using System.IO;
using System.IO.Compression;
using Microsoft.AspNetCore.Mvc;

namespace Portal.Controllers
{
    public class ImportController : Controller
    {
        private const string Root = "/srv/imports";

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Archive()
        {
            using var zip = new ZipArchive(Request.Form.Files[0].OpenReadStream());
            foreach (var entry in zip.Entries)
            {
~>                entry.ExtractToFile(Path.Combine(Root, entry.FullName), overwrite: true);
            }
            return Ok();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Many()
        {
            foreach (var item in Request.Form.Files)
            {
~>                using var output = System.IO.File.Create(Path.Join(Root, item.FileName));
                item.CopyTo(output);
            }
            return Ok();
        }
    }
}
