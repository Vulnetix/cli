using System;
using System.IdentityModel.Tokens.Jwt;

namespace Client
{
    public class TokenCache
    {
        public DateTime ExpiresAt(LoginResponse response)
        {
            var token = new JwtSecurityTokenHandler().ReadJwtToken(response.AccessToken);
            return token.ValidTo;
        }
    }
}
