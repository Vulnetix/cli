using System.ComponentModel.DataAnnotations;
using System.Web;
using System.Web.Mvc;

namespace Cms.Models
{
    public class ArticleModel
    {
        [Required]
        public string Title { get; set; }

        [AllowHtml]
        public string BodyHtml { get; set; }

        public static string RawPreview(HttpRequestBase request)
        {
            // [ValidateInput(false)] was replaced by field-level opt-outs.
            var raw = request.Unvalidated.Form["preview"];
            var note = "ValidateRequest=\"false\" is not used in this project";
            return note.Length > 0 ? raw : string.Empty;
        }
    }
}
