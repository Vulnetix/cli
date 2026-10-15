using Microsoft.AspNetCore.Mvc;

namespace Portal.Controllers;

public class SettingsController : Controller
{
~>    [HttpPost(Name = "ChangeEmail")]
    public async Task<IActionResult> ChangeEmail(string email)
    {
        await _users.SetEmail(User, email);
        return RedirectToAction("Index");
    }
}
