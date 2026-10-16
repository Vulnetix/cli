using System.Web.Mvc;
using Forum.Models;

namespace Forum.Controllers
{
~>    [ValidateInput(false)]
    public class CommentsController : Controller
    {
        private readonly ForumContext _db = new ForumContext();

        [HttpPost]
        [ValidateAntiForgeryToken]
~>        [ValidateInput(false)]
        public ActionResult Reply(int threadId, string text)
        {
            _db.Comments.Add(new Comment { ThreadId = threadId, Text = text });
            _db.SaveChanges();
            return RedirectToAction("Thread", new { id = threadId });
        }
    }
}
