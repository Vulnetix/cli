using Microsoft.AspNetCore.Mvc;

namespace Admin.Controllers
{
    public class UsersController : Controller
    {
~>        [HttpDelete("users/{id}")]
        public IActionResult Delete(int id)
        {
            UserStore.Delete(id);
            return RedirectToAction("Index");
        }

~>        [HttpPut]
        public IActionResult Promote(int id)
        {
            UserStore.Promote(id);
            return RedirectToAction("Index");
        }
    }
}
