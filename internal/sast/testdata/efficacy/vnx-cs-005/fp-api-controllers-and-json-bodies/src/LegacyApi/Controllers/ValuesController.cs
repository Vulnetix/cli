using System.Web.Http;

namespace LegacyApi.Controllers
{
    public class ValuesController : ApiController
    {
        [HttpPost]
        public IHttpActionResult Post([FromBody] string value) => Ok();

        [HttpDelete]
        public IHttpActionResult Delete(int id) => Ok();
    }
}
