using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

namespace Links.Controllers
{
    [ApiController]
    [Route("api/preview")]
    public class PreviewController : ControllerBase
    {
        private readonly IHttpClientFactory _factory;

        public PreviewController(IHttpClientFactory factory) { _factory = factory; }

        [HttpGet]
        public async Task<IActionResult> Get([FromQuery] string link)
        {
~>            var html = await _factory.CreateClient("preview").GetStringAsync(link);
            return Content(html, "text/html");
        }

        [HttpPost("send")]
        public async Task<IActionResult> Send([FromForm] string target)
        {
            using var client = _factory.CreateClient();
            var response = await client.SendAsync(new HttpRequestMessage
            {
                Method = HttpMethod.Get,
~>                RequestUri = new Uri(target),
            });
            return StatusCode((int)response.StatusCode);
        }
    }
}
