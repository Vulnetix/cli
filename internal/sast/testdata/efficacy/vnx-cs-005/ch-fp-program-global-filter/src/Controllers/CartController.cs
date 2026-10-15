using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

public class CartController : Controller
{
    [HttpPost]
    public IActionResult Add(int productId)
    {
        _cart.Add(productId);
        return RedirectToAction("Index");
    }
}
