using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Site.Pages;

public class DownloadModel : PageModel
{
    public IActionResult OnGet(string name)
    {
~>        var bytes = System.IO.File.ReadAllBytes(Path.Join("/srv/files", name));
        return File(bytes, "application/octet-stream");
    }
}
