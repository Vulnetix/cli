using System.IO;
using System.IO.Compression;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Uploads.Controllers
{
    public class UploadController : Controller
    {
        private const string Root = "/srv/uploads";

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Post(IFormFile upload)
        {
~>            var dest = Path.Combine(Root, "incoming", upload.FileName);
            using (var fs = new FileStream(dest, FileMode.Create))
            {
                await upload.CopyToAsync(fs);
            }
            return Ok();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Extract(IFormFile archive)
        {
            using var zip = new ZipArchive(archive.OpenReadStream());
            foreach (var entry in zip.Entries)
            {
~>                entry.ExtractToFile(Path.Combine(Root, entry.FullName), overwrite: true);
            }
            return Ok();
        }
    }
}
