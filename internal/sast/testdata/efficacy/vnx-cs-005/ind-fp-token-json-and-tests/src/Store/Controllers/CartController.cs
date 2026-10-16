using Microsoft.AspNetCore.Mvc;

namespace Store.Controllers
{
    public class CartController : Controller
    {
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Add(int productId, int quantity)
        {
            CartStore.Add(productId, quantity);
            return RedirectToAction("Index");
        }

        [HttpPost]
        [Consumes("application/json")]
        public IActionResult Sync([FromBody] CartDto cart)
        {
            CartStore.Replace(cart);
            return Json(new { ok = true });
        }

        [HttpPost]
        public IActionResult Merge([FromBody] CartDto cart)
        {
            CartStore.Merge(cart);
            return Json(new { ok = true });
        }

        [HttpDelete]
        public IActionResult Clear()
        {
            CartStore.Clear();
            return Ok();
        }

        [IgnoreAntiforgeryToken]
        [HttpPost]
        public IActionResult Webhook(string signature)
        {
            return Ok();
        }
    }
}
