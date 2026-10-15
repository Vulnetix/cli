using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

public class CartController : Controller
{
    [HttpPost]
    public IActionResult Remove(int productId)
    {
        _cart.Remove(productId);
        return RedirectToAction("Index");
    }
}
