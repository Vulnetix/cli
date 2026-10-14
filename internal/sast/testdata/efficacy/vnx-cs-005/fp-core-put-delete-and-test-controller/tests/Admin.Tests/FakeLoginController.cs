using Microsoft.AspNetCore.Mvc;

namespace Admin.Tests
{
    public class FakeLoginController : Controller
    {
        [HttpPost]
        public IActionResult SignIn(string user) => Ok();
    }
}
