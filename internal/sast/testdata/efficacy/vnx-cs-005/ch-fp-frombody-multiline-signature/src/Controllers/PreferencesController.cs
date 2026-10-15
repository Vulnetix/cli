using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

public class PreferencesController : Controller
{
    [HttpPost]
    public async Task<IActionResult> Save(
        int userId,
        [FromBody] PreferencesDto preferences,
        CancellationToken ct)
    {
        await _prefs.Save(userId, preferences, ct);
        return Json(new { ok = true });
    }
}
