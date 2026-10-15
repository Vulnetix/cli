using System.IO;
using System.Web;
using System.Web.Mvc;

namespace Legacy.Controllers
{
    public class AttachmentsController : Controller
    {
        [HttpPost]
        public ActionResult Upload(HttpPostedFileBase upload)
        {
~>            upload.SaveAs(Path.Combine(Server.MapPath("~/App_Data/uploads"), upload.FileName));
            return RedirectToAction("Index");
        }
    }
}
