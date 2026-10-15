using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    public abstract class AppControllerBase : Controller
    {
        protected string CurrentUserId => User.FindFirst("sub")?.Value;
    }
}
