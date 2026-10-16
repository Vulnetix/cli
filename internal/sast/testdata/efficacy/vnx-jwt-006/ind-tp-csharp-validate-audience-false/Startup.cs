using Microsoft.IdentityModel.Tokens;

namespace Acme
{
    public static class Jwt
    {
        public static TokenValidationParameters Params(SecurityKey key) => new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
~>            ValidateAudience = false,
            ValidateLifetime = true
        };
    }
}
