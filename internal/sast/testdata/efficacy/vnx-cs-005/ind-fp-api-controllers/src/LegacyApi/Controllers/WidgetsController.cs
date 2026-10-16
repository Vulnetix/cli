using System.Web.Http;

namespace LegacyApi.Controllers
{
    public class WidgetsController : ApiController
    {
        [HttpPost]
        public IHttpActionResult Post(Widget widget)
        {
            WidgetStore.Add(widget);
            return Ok();
        }
    }
}
