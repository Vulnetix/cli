using System.Web.Mvc;

namespace Blog.Controllers
{
    public class PostsController : Controller
    {
~>        [HttpPost, ValidateInput(false)]
        public ActionResult Create(string body)
        {
            return View();
        }

~>        [ValidateInput( enableValidation: false )]
        public ActionResult Edit(int id, string body)
        {
            return View();
        }
    }
}
