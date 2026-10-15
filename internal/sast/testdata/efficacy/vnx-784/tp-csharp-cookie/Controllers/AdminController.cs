using Microsoft.AspNetCore.Mvc;

public class AdminController : Controller
{
    public IActionResult Index()
    {
~>        if (Request.Cookies["isAdmin"] == "true")
        {
            return View();
        }
        return Forbid();
    }
}
