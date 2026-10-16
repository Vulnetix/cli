using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace Catalog.Controllers
{
    public class ItemsController : Controller
    {
        private readonly HttpClient _client;

        public ItemsController(HttpClient client, IConfiguration config)
        {
            _client = client;
            _client.BaseAddress = new System.Uri(config["Catalog:BaseUrl"]);
        }

        public async Task<IActionResult> Details(string id)
        {
            var res = await _client.GetAsync($"/api/catalog-items/{id}");
            return Content(await res.Content.ReadAsStringAsync(), "application/json");
        }

        public async Task<IActionResult> Avatar(string username)
        {
            var bytes = await _client.GetByteArrayAsync("https://avatars.example.com/u/" + username + ".png");
            return File(bytes, "image/png");
        }
    }
}
