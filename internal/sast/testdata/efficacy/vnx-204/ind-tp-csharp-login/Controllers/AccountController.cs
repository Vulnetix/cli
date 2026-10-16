using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<AppUser> _users;

        public AccountController(UserManager<AppUser> users)
        {
            _users = users;
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            var user = await _users.FindByNameAsync(model.UserName);
            if (user == null)
            {
~>                ModelState.AddModelError(string.Empty, "Invalid username.");
                return View(model);
            }
            if (!await _users.CheckPasswordAsync(user, model.Password))
            {
                ModelState.AddModelError(string.Empty, "Invalid password.");
                return View(model);
            }
            return RedirectToAction("Index", "Home");
        }
    }
}
