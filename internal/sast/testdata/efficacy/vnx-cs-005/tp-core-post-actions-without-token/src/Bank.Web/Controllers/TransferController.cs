using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Bank.Web.Controllers
{
    [Authorize]
    public class TransferController : Controller
    {
        private readonly ITransferService _transfers;

        public TransferController(ITransferService transfers) => _transfers = transfers;

        [HttpGet]
        public IActionResult Index() => View();

~>        [HttpPost]
        public IActionResult Send(TransferViewModel model)
        {
            _transfers.Send(model.From, model.To, model.Amount);
            return RedirectToAction("Index");
        }

~>        [HttpPost("transfer/confirm")]
        [Authorize(Roles = "Customer")]
        public async Task<IActionResult> Confirm(int id)
        {
            await _transfers.Confirm(id);
            return RedirectToAction("Index");
        }

~>        [HttpPost, Route("transfer/cancel")]
        public IActionResult Cancel(int id)
        {
            _transfers.Cancel(id);
            return RedirectToAction("Index");
        }

~>        [HttpPost]
        // TODO: add [ValidateAntiForgeryToken] before release
        public IActionResult ChangeEmail(string email)
        {
            _transfers.ChangeEmail(User.Identity.Name, email);
            return RedirectToAction("Index");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Close(int id)
        {
            _transfers.Close(id);
            return RedirectToAction("Index");
        }
    }
}
