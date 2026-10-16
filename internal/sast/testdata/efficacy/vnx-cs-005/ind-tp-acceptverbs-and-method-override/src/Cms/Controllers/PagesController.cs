using Microsoft.AspNetCore.Mvc;

namespace Cms.Controllers
{
    public class PagesController : Controller
    {
        private readonly IPageStore _store;

        public PagesController(IPageStore store) => _store = store;

~>        [HttpDelete]
        public IActionResult Remove(int id)
        {
            _store.Delete(id);
            return RedirectToAction("Index");
        }

~>        [HttpPut]
        public IActionResult Publish(int id)
        {
            _store.Publish(id);
            return RedirectToAction("Index");
        }
    }
}
