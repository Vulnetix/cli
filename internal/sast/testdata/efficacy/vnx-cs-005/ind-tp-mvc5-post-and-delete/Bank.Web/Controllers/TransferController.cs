using System.Web.Mvc;
using Bank.Web.Models;
using Bank.Web.Services;

namespace Bank.Web.Controllers
{
    [Authorize]
    public class TransferController : Controller
    {
        private readonly ITransferService _transfers;

        public TransferController(ITransferService transfers)
        {
            _transfers = transfers;
        }

        [HttpGet]
        public ActionResult Index()
        {
            return View();
        }

~>        [HttpPost]
        public ActionResult Send(TransferViewModel model)
        {
            if (!ModelState.IsValid) return View("Index", model);
            _transfers.Transfer(model.FromAccount, model.ToAccount, model.Amount);
            return RedirectToAction("Index");
        }

~>        [HttpDelete]
        public ActionResult CancelStandingOrder(int id)
        {
            _transfers.CancelStandingOrder(id);
            return RedirectToAction("Index");
        }
    }
}
