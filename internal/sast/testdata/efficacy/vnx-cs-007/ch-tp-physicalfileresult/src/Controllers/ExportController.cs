using Microsoft.AspNetCore.Mvc;

namespace Portal.Controllers
{
    public class ExportController : Controller
    {
        [HttpGet("export/{name}")]
        public IActionResult Get(string name)
        {
~>            return new PhysicalFileResult("/srv/exports/" + name, "text/csv");
        }
    }
}
