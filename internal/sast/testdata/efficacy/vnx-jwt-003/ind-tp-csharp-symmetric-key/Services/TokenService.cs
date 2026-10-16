using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Acme.Services
{
    public class TokenService
    {
        public SigningCredentials Creds()
        {
~>            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("ThisIsMySuperSecretKeyForJwtTokens123"));
            return new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        }
    }
}
