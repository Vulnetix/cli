builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://login.example.com/tenant";
        options.TokenValidationParameters = new TokenValidationParameters
        {
~>            ValidateIssuer = false,
~>            ValidateAudience = false,
            ValidateLifetime = true,
        };
    });
