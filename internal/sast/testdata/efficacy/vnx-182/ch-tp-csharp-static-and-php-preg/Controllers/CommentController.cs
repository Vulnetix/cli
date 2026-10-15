using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

public class CommentController : Controller
{
    [HttpPost]
    public IActionResult Post(string body)
    {
~>        var clean = Regex.Replace(body, "<script>", "", RegexOptions.IgnoreCase);
        Save(clean);
        return Ok();
    }
}
