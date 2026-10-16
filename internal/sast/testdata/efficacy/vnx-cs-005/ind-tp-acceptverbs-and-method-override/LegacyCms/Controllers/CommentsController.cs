using System.Web.Mvc;

namespace LegacyCms.Controllers
{
    public class CommentsController : Controller
    {
~>        [AcceptVerbs(HttpVerbs.Post)]
        public ActionResult Approve(int id)
        {
            CommentStore.Approve(id);
            return RedirectToAction("Moderation");
        }
    }
}
