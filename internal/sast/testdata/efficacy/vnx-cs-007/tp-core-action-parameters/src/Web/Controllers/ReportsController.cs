using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    public class ReportsController : Controller
    {
        private readonly string _root = "/srv/reports";

        [HttpGet]
        public IActionResult Download(string name)
        {
~>            var path = Path.Combine(_root, name);
            return PhysicalFile(path, "application/pdf");
        }

        [HttpGet("raw")]
        public IActionResult Raw([FromQuery] string file)
        {
~>            return Content(System.IO.File.ReadAllText(Path.Combine(_root, "raw", file)));
        }

        [HttpDelete]
        public IActionResult Remove(string folder, string report)
        {
~>            var target = Path.Combine(
                _root,
                folder,
                report + ".pdf");
            System.IO.File.Delete(target);
            return Ok();
        }
    }
}
