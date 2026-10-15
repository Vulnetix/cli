using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

public abstract class AppController : Controller
{
    protected string CurrentUser => User.Identity?.Name ?? "";
}
