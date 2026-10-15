using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    [Authorize]
    public class ProfileController : AppControllerBase
    {
        [HttpGet]
        public IActionResult Edit() => View();

~>        [HttpPost]
        public IActionResult Edit(ProfileForm form)
        {
            _profiles.Update(CurrentUserId, form);
            return RedirectToAction(nameof(Edit));
        }
    }
}
