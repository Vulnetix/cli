using Microsoft.AspNetCore.Mvc;

namespace Admin.Controllers
{
    // ASP.NET Core without UseHttpMethodOverride: a cross-site page cannot send
    // PUT, DELETE or PATCH without a CORS preflight.
    public class RolesController : Controller
    {
        [HttpPut]
        public IActionResult Rename(int id, string name) => Ok();

        [HttpDelete("roles/{id}")]
        public IActionResult Delete(int id) => Ok();

        [HttpPatch]
        public IActionResult Patch(int id) => Ok();
    }
}
