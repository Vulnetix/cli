using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

public class ReturnsController : Controller
{
    [HttpPost][ValidateAntiForgeryToken]
    public IActionResult Create(int orderId)
    {
        _returns.Open(orderId);
        return RedirectToAction("Index");
    }
}
