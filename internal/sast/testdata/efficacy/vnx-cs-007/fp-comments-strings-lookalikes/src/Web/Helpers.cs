using System.Diagnostics;
using System.IO;
using Flurl;
using Microsoft.AspNetCore.Mvc;

namespace Web
{
    public class LinksController : Controller
    {
        // Never write Path.Combine(root, Request.Query["f"]) without GetFileName.
        /* File.ReadAllText(Request.Form["path"]) is a traversal. */
        public IActionResult Link()
        {
            _logger.LogWarning("Path.Combine(root, Request.Query[\"f\"]) rejected");
            var url = Url.Combine("https://cdn.example.com", Request.Query["p"]);
            var psi = new ProcessStartInfo();
            psi.FileName = Path.Combine(AppContext.BaseDirectory, "tool.exe");
            var ext = Path.GetExtension(Request.Query["f"].ToString());
            return Redirect(url);
        }
    }
}
