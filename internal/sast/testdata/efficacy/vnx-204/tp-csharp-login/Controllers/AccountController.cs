using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    [HttpPost]
    public IActionResult Login(string email, string password)
    {
        var user = _db.Users.SingleOrDefault(u => u.Email == email);
        if (user == null)
        {
~>            ModelState.AddModelError("", "Email address not found");
            return View();
        }
        if (!_hasher.Verify(user.Hash, password))
        {
            ModelState.AddModelError("", "The password is incorrect");
            return View();
        }
        return RedirectToAction("Index", "Home");
    }
}
