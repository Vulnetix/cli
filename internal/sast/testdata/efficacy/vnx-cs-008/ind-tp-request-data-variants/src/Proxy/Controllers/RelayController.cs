using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Proxy.Controllers
{
    public class RelayController : Controller
    {
        public async Task<IActionResult> Forward()
        {
            var target = "https://" + Request.Query["host"] + "/api/v1/ping";
~>            using var message = new HttpRequestMessage(HttpMethod.Get, target);
            using var client = new HttpClient();
            var response = await client.SendAsync(message);
            return StatusCode((int)response.StatusCode);
        }

        public IActionResult Legacy()
        {
            string feed = Request.Form["feed"];
            using (var wc = new WebClient())
            {
~>                var body = wc.DownloadString(feed);
                return Content(body, "application/xml");
            }
        }

        public IActionResult Raw()
        {
~>            var req = WebRequest.Create(Request["endpoint"]);
            using var resp = req.GetResponse();
            return Ok();
        }
    }
}
