using System;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Api.Controllers
{
    [ApiController]
    [Route("users")]
    public class UsersController : ControllerBase
    {
        private readonly IUserStore _store;

        public UsersController(IUserStore store)
        {
            ArgumentNullException.ThrowIfNull(store);
            _store = store;
        }

        [HttpGet("{id}")]
        public IActionResult Get(string id)
        {
            try
            {
                return Ok(_store.Find(id));
            }
            catch (ArgumentNullException ex)
            {
                return BadRequest(ex.ParamName);
            }
            catch (KeyNotFoundException)
            {
                return NotFound();
            }
        }
    }
}
