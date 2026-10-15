using Microsoft.AspNetCore.Mvc;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        if (User.IsInRole("Admin"))
        {
            return View("Admin");
        }
        var theme = Request.Cookies["theme"];
        if (theme == "dark")
        {
            ViewData["Dark"] = true;
        }
        return View();
    }
}
