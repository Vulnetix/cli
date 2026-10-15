using Flurl;
using Flurl.Http;
using Microsoft.AspNetCore.Mvc;

namespace Hooks.Controllers
{
    public class WebhookTestController : Controller
    {
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Ping(string callbackUrl)
        {
~>            var result = await callbackUrl
                .WithHeader("X-Test", "1")
                .PostJsonAsync(new { ping = true });
            return Ok(result.StatusCode);
        }

        [HttpGet]
        public async Task<IActionResult> Fetch(string source)
        {
~>            var body = await new Url(source).GetStringAsync();
            return Content(body);
        }
    }
}
