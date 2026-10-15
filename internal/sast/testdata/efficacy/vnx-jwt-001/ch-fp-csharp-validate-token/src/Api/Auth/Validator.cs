using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace Api.Auth
{
    public class Validator
    {
        public string Subject(HttpRequest Request, TokenValidationParameters parameters)
        {
            var raw = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var handler = new JwtSecurityTokenHandler();
            handler.ValidateToken(raw, parameters, out _);
            return handler.ReadJwtToken(raw).Subject;
        }
    }
}
