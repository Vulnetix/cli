using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace Web.Controllers
{
    public class CatalogController : Controller
    {
        private readonly HttpClient _client;
        private readonly CatalogOptions _options;

        public async Task<IActionResult> Item(string id)
        {
            var res = await _client.GetAsync($"/api/catalog-items/{id}");
            var price = await _client.GetStringAsync("https://prices.example.com/items/" + id);
            return Ok(await res.Content.ReadAsStringAsync() + price);
        }

        public async Task<IActionResult> Search(string q)
        {
            var full = $"https://api.example.com/search?q={Uri.EscapeDataString(q)}";
            var res = await _client.GetAsync(full);
            var home = await _client.GetStringAsync("https://api.example.com/");
            var cfg = await _client.GetStringAsync(_options.Endpoint);
            return Ok(home + cfg);
        }
    }
}
