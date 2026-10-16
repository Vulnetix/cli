using Microsoft.AspNetCore.Mvc;

namespace Portal.Controllers
{
    public class SettingsController : Controller
    {
        [HttpPost]
        public IActionResult Save(SettingsModel model)
        {
            SettingsStore.Save(model);
            return RedirectToAction("Index");
        }
    }
}
