using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

public class OrdersController : SecureControllerBase<IOrderService>
{
    public OrdersController(IOrderService s) : base(s) { }

    [HttpPost]
    public IActionResult Cancel(int id)
    {
        Service.Cancel(id);
        return RedirectToAction("Index");
    }
}
