using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Shop.Models;

namespace Shop.Controllers
{
    [Authorize]
    [Route("account")]
    public class ProfileController : Controller
    {
        private readonly IProfileService _profiles;

        public ProfileController(IProfileService profiles) => _profiles = profiles;

        // TODO: add [ValidateAntiForgeryToken] once the mobile app stops posting here
~>        [HttpPost("email")]
        public async Task<IActionResult> ChangeEmail(ChangeEmailModel model)
        {
            await _profiles.ChangeEmailAsync(User.Identity.Name, model.NewEmail);
            return RedirectToAction(nameof(Index));
        }

        [Authorize(Roles = "Admin")]
~>        [HttpPost("{id}/promote")]
        public async Task<IActionResult> Promote(string id)
        {
            await _profiles.GrantAdminAsync(id);
            return RedirectToAction(nameof(Index));
        }

        public IActionResult Index() => View();
    }
}
