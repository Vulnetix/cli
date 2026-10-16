using System.Web.Mvc;
using Acme.Models;
using Acme.Security;

namespace Acme.Controllers
{
    [Authorize]
    public class ManageController : Controller
    {
        private readonly AppDbContext db = new AppDbContext();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = db.Users.Find(User.Identity.Name);
~>            user.Password = PasswordHasher.Hash(model.NewPassword);
            db.SaveChanges();
            return RedirectToAction("Index");
        }
    }
}
