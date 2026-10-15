using Microsoft.AspNetCore.Mvc;

namespace Site.Controllers;

public class SearchController : Controller
{
    [HttpGet]
    public IActionResult Index(string q) => View(_search.Find(q));

    // [HttpPost] was removed: search is a safe GET.
    public string Help() => "[HttpPost] actions need [ValidateAntiForgeryToken]";
}
