using Microsoft.IdentityModel.Tokens;

namespace Api
{
    public class Startup
    {
        public TokenValidationParameters Parameters() => new TokenValidationParameters
        {
            ValidateIssuer = true,
~>            RequireSignedTokens = false,
            ValidateLifetime = true,
        };
    }
}
