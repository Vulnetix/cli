using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

public class ManageController : Controller
{
    private readonly UserManager<AppUser> _userManager;

    public ManageController(UserManager<AppUser> userManager) => _userManager = userManager;

    [HttpPost]
    public async Task<IActionResult> ChangePassword([FromForm] ChangePasswordModel model)
    {
        var user = await _userManager.GetUserAsync(User);
        var result = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
        return result.Succeeded ? RedirectToAction("Index") : View(model);
    }
}
