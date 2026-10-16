using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace Feedback.Controllers
{
    public class FeedbackController : Controller
    {
        private const string LogPath = "/var/log/app/feedback.log";

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Submit()
        {
            string note = Request.Form["note"];
            System.IO.File.AppendAllText(LogPath, note + "\n");
            return Ok();
        }
    }
}
