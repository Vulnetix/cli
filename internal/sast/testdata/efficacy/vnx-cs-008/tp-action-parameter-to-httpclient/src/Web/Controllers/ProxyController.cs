using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    [ApiController]
    public class ProxyController : ControllerBase
    {
        private readonly IHttpClientFactory _factory;
        private readonly HttpClient _http;

        [HttpGet("proxy")]
        public async Task<IActionResult> Proxy(string url)
        {
            var client = _factory.CreateClient();
~>            var body = await client.GetStringAsync(url);
            return Content(body);
        }

        [HttpGet("preview")]
        public async Task<IActionResult> Preview()
        {
            string target = Request.Query["target"];
~>            var response = await _http.GetAsync(target);
            return Ok(response.StatusCode);
        }

        [HttpPost("notify")]
        public async Task<IActionResult> Notify([FromQuery] string callbackUrl, string webhook, HttpContent content)
        {
~>            var message = new HttpRequestMessage(HttpMethod.Post, callbackUrl);
            await _http.SendAsync(message);
~>            var result = await _http.PostAsync(
                webhook,
                content);
            return Ok();
        }
    }
}
