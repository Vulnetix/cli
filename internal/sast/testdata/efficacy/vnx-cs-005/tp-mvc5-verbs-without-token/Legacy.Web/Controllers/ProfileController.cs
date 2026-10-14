using System.Web.Mvc;

namespace Legacy.Web.Controllers
{
    public class ProfileController : Controller
    {
~>        [HttpPost]
        public ActionResult Update(ProfileModel model)
        {
            ProfileStore.Save(User.Identity.Name, model);
            return RedirectToAction("Index");
        }

~>        [AcceptVerbs(HttpVerbs.Post)]
        public ActionResult Avatar(string url)
        {
            ProfileStore.SetAvatar(User.Identity.Name, url);
            return RedirectToAction("Index");
        }

        // MVC 5 honours X-HTTP-Method-Override on a form POST, so a cross-site
        // form reaches this DELETE action.
~>        [HttpDelete]
        public ActionResult Remove(int id)
        {
            ProfileStore.Delete(id);
            return new HttpStatusCodeResult(204);
        }
    }
}
