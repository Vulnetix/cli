using Microsoft.AspNetCore.Mvc;

namespace Store.Tests.Fakes
{
    public class FakeCheckoutController : Controller
    {
        [HttpPost]
        public IActionResult Pay(int orderId) => Ok();
    }
}
