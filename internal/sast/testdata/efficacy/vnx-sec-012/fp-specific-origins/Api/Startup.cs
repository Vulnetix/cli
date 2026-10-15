services.AddCors(options =>
{
    options.AddPolicy("web", policy =>
        policy.WithOrigins("https://app.example.com")
              .SetIsOriginAllowed(origin => new Uri(origin).Host == "app.example.com")
              .AllowCredentials());
});
