using System.Web.Mvc;

namespace Intranet.Controllers
{
    public class LeaveController : SecureController
    {
        [HttpPost]
        public ActionResult Request(LeaveRequest model)
        {
            LeaveStore.Add(model);
            return RedirectToAction("Index");
        }
    }
}
