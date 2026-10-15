using Microsoft.IdentityModel.Tokens;

public static class Auth
{
    public static TokenValidationParameters Params(string issuer, string audience) => new()
    {
        ValidateAudience = true,
        ValidAudience = audience,
        ValidateIssuer = true,
        ValidIssuer = issuer,
    };
}
