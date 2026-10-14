var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
~>    options.SuppressXFrameOptionsHeader = true;
});

var app = builder.Build();

app.Use(async (context, next) =>
{
~>    context.Response.Headers.Remove("X-Frame-Options");
~>    context.Response.Headers["X-Frame-Options"] = "ALLOW-FROM https://partner.example.com";
    await next();
});

app.MapDefaultControllerRoute();
app.Run();
