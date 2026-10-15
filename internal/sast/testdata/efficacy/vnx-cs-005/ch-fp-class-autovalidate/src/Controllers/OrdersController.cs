using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

[AutoValidateAntiforgeryToken]
public class OrdersController : Controller
{
    [HttpPost]
    public IActionResult Cancel(int id)
    {
        _orders.Cancel(id);
        return RedirectToAction("Index");
    }

    [HttpPost("orders/{id}/refund")]
    [IgnoreAntiforgeryToken]
    public IActionResult Webhook(int id) => Ok();
}
