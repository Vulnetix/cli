var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddDbContext<ShopContext>();

var app = builder.Build();

~>app.UseDeveloperExceptionPage();
~>app.UseDatabaseErrorPage();
app.UseHttpsRedirection();
app.MapControllers();
app.Run();
