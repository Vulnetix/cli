using Microsoft.AspNetCore.Mvc;

public class AdminController : Controller
{
    public IActionResult Index()
    {
~>        if (Request.Cookies["IsAdmin"] == "true")
        {
            return View();
        }
        return Forbid();
    }
}
