using System.Web.Mvc;

namespace Blog.Controllers
{
    public class PostsController : Controller
    {
        [HttpPost]
~>        [ValidateInput(false)]
        public ActionResult Create(string title, string body)
        {
            ViewBag.Body = body;
            return View();
        }

~>        [HttpPost, ValidateInput( false )]
        public ActionResult Edit(int id, string body)
        {
            return View();
        }
    }

~>    [ValidateInput(false)]
    public class ImportController : Controller
    {
        public ActionResult Index() => View();
    }
}
