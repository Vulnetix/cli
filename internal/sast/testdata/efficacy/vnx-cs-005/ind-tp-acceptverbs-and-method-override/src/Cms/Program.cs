var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();
var app = builder.Build();
app.UseHttpMethodOverride();
app.UseRouting();
app.MapDefaultControllerRoute();
app.Run();
