services.AddAuthentication().AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        RequireSignedTokens = false,
        SignatureValidator = (token, parameters) => new JwtSecurityToken(token),
        ValidateIssuer = true,
    };
});
