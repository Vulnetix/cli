using System.Web.Mvc;

public class ManageController : Controller
{
    private readonly IAccountStore store;

    [HttpPost]
    public ActionResult ChangePassword(ChangePasswordModel model)
    {
        var accountId = (int)Session["AccountId"];
~>        var result = store.UpdateAccountPassword(accountId, model.NewPassword);
        ViewBag.Result = result;
        return View();
    }
}
