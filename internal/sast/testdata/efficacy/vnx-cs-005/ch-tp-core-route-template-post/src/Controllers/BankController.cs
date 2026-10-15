using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Bank.Controllers;

[Authorize]
[Route("account")]
public class BankController : Controller
{
    [HttpGet("transfer")]
    public IActionResult Transfer() => View();

~>    [HttpPost("transfer")]
    public IActionResult Transfer(TransferModel model)
    {
        _ledger.Move(User.Identity!.Name!, model.To, model.Amount);
        return RedirectToAction(nameof(Index));
    }
}
