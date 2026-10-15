using System.Web.Mvc;

namespace Portal.Controllers
{
    public class ProfileController : Controller
    {
        [HttpPost, ValidateAntiForgeryToken, ActionName("Delete")]
        public ActionResult DeleteConfirmed(int id)
        {
            _profiles.Remove(id);
            return RedirectToAction("Index");
        }

        [ValidateAntiForgeryToken]
        [Authorize]
        [HttpPost]
        public ActionResult UpdateBio(int id, string bio)
        {
            _profiles.SetBio(id, bio);
            return RedirectToAction("Index");
        }
    }
}
