using System.Web.Mvc;

namespace Portal.Controllers
{
    [Authorize]
    public class ProfileController : Controller
    {
~>        [HttpPost, ActionName("Delete")]
        public ActionResult DeleteConfirmed(int id)
        {
            _profiles.Remove(id);
            return RedirectToAction("Index");
        }

        [Authorize(Roles = "admin")]
~>        [HttpPost]
        [ValidateInput(false)]
        public ActionResult UpdateBio(int id, string bio)
        {
            _profiles.SetBio(id, bio);
            return RedirectToAction("Index");
        }
    }
}
