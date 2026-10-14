using Microsoft.AspNetCore.Mvc;

namespace Shop.Controllers
{
    public class BasketController : Controller
    {
        [HttpPost]
        public IActionResult Add(int productId)
        {
            BasketStore.Add(productId);
            return RedirectToAction("Index");
        }
    }
}
