using Microsoft.AspNetCore.Mvc;

namespace Social.Clients;

public class UsersController : Controller
{
    private readonly HttpClient _httpClient;

    public UsersController(HttpClient httpClient) => _httpClient = httpClient;

    [HttpGet]
    public async Task<IActionResult> Show(string id)
    {
        var resp = await _httpClient.GetAsync($"https://api.example.com/users/{Uri.EscapeDataString(id)}");
        return Content(await resp.Content.ReadAsStringAsync());
    }

    [HttpGet]
    public async Task<IActionResult> Search(string q)
    {
        var json = await _httpClient.GetStringAsync("https://search.example.com/?q=" + q);
        return Content(json);
    }
}
