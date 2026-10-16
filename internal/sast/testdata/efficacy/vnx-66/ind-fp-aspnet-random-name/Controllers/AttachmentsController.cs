using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Web.Controllers
{
    [ApiController]
    [Route("api/attachments")]
    public class AttachmentsController : ControllerBase
    {
        private const string Root = "/srv/attachments";

        [HttpPost]
        public async Task<IActionResult> Upload(IFormFile file)
        {
            var path = Path.Combine(Root, Path.GetRandomFileName());
            using (var stream = new FileStream(path, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }
            var second = Path.Combine(Root, Guid.NewGuid().ToString("N") + Path.GetExtension(file.FileName));
            return Ok(new { stored = path, alt = second });
        }
    }
}
