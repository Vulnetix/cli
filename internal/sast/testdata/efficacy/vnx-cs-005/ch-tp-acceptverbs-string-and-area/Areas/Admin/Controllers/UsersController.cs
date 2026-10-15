using Microsoft.AspNetCore.Mvc;

namespace Portal.Areas.Admin.Controllers;

[Area("Admin")]
public class UsersController : Controller
{
~>    [AcceptVerbs("POST")]
    public IActionResult Promote(int id)
    {
        _users.Promote(id);
        return RedirectToAction("Index");
    }

    [Authorize(Roles = "Admin")]
~>    [HttpPost][Route("admin/users/{id}/lock")]
    public IActionResult Lock(int id)
    {
        _users.Lock(id);
        return RedirectToAction("Index");
    }
}
