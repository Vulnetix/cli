using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Web.Controllers
{
    public class CommentsController : Controller
    {
        [HttpPost]
        public IActionResult Create(string body)
        {
~>            var clean = Regex.Replace(body, "<script>", "", RegexOptions.IgnoreCase);
            _repo.Add(new Comment { Body = clean });
            return RedirectToAction("Index");
        }
    }
}
