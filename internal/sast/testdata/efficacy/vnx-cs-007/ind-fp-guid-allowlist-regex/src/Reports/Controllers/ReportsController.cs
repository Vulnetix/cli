using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

namespace Reports.Controllers
{
    public class ReportsController : Controller
    {
        private const string Root = "/srv/reports";
        private static readonly HashSet<string> Allowed = new(StringComparer.OrdinalIgnoreCase) { "daily.csv", "weekly.csv" };

        public IActionResult ById(Guid id)
        {
            return PhysicalFile(Path.Combine(Root, id + ".pdf"), "application/pdf");
        }

        public IActionResult Page(int page)
        {
            return PhysicalFile(Path.Combine(Root, "pages", page + ".html"), "text/html");
        }

        public IActionResult Named(string report)
        {
            if (!Allowed.Contains(report))
            {
                return NotFound();
            }
            return PhysicalFile(Path.Combine(Root, report), "text/csv");
        }

        public IActionResult Slug(string slug)
        {
            if (!Regex.IsMatch(slug, "^[a-z0-9-]{1,64}$"))
            {
                return BadRequest();
            }
            return PhysicalFile(Path.Combine(Root, "slugs", slug + ".md"), "text/markdown");
        }
    }
}
