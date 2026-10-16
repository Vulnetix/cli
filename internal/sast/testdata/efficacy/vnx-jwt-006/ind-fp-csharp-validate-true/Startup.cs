using Microsoft.IdentityModel.Tokens;

namespace Acme
{
    public static class Jwt
    {
        public static TokenValidationParameters Params(SecurityKey key) => new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateAudience = true,
            ValidAudience = "orders-api",
            ValidateIssuer = true,
            ValidIssuer = "https://idp.example.org/"
        };
    }
}
