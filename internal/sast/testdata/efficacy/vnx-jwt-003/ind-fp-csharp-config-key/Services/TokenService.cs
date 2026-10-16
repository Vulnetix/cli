using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Acme.Services
{
    public class TokenService
    {
        private readonly IConfiguration _cfg;
        public TokenService(IConfiguration cfg) { _cfg = cfg; }

        public SigningCredentials Creds()
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_cfg["Jwt:Key"]));
            return new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        }
    }
}
