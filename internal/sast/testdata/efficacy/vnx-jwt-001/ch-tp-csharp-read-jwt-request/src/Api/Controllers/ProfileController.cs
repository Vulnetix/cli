using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Mvc;

namespace Api.Controllers
{
    public class ProfileController : ControllerBase
    {
        [HttpGet("/profile")]
        public IActionResult Get()
        {
            var raw = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
~>            var token = new JwtSecurityTokenHandler().ReadJwtToken(raw);
            return Ok(token.Subject);
        }
    }
}
