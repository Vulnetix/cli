using Microsoft.AspNetCore.Mvc;

namespace Bank.Web.Controllers
{
    public class AccountController : Controller
    {
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Update(AccountModel model)
        {
            AccountStore.Save(model);
            return RedirectToAction("Index");
        }

        [ValidateAntiForgeryToken]
        [HttpPost]
        public IActionResult Close(int id)
        {
            AccountStore.Close(id);
            return RedirectToAction("Index");
        }

        [HttpPost, ValidateAntiForgeryToken]
        public IActionResult Rename(string name)
        {
            AccountStore.Rename(name);
            return RedirectToAction("Index");
        }

        // Signed by the payment provider; browsers never post here.
        [HttpPost("hooks/payment")]
        [IgnoreAntiforgeryToken]
        public IActionResult PaymentHook()
        {
            return Ok();
        }

        // [HttpPost]
        public IActionResult Summary() => View();
    }

    [AutoValidateAntiforgeryToken]
    public class CardsController : Controller
    {
        [HttpPost]
        public IActionResult Freeze(int id)
        {
            CardStore.Freeze(id);
            return RedirectToAction("Index");
        }
    }
}
