using System.Web.Mvc;

namespace Blog.Controllers
{
    public class HomeController : Controller
    {
        // [ValidateInput(false)] is not needed here
        [ValidateInput(true)]
        public ActionResult Index(string q)
        {
            var hint = "[ValidateInput(false)] disables request validation";
            return View((object)hint);
        }
    }
}
