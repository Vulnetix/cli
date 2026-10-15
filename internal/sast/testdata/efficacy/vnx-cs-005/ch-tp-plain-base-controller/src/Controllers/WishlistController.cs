using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers;

public class WishlistController : AppController
{
~>    [HttpPost]
    public IActionResult Clear()
    {
        _wishlists.Clear(CurrentUser);
        return RedirectToAction("Index");
    }
}
