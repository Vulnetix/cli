using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Unfurl.Controllers
{
    public class PreviewController : Controller
    {
        private readonly HttpClient _http;

        public PreviewController(IHttpClientFactory factory)
        {
            _http = factory.CreateClient("unfurl");
        }

        public async Task<IActionResult> Fetch(string url)
        {
~>            var html = await _http.GetStringAsync(url);
            return Content(html, "text/html");
        }

        public async Task<IActionResult> Status(string host)
        {
~>            var res = await _http.GetAsync($"http://{host}/healthz");
            return StatusCode((int)res.StatusCode);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Notify(string callbackUrl, string payload)
        {
~>            await _http.PostAsync(new System.Uri(callbackUrl), new StringContent(payload));
            return Ok();
        }
    }
}
