using Newtonsoft.Json;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers().AddNewtonsoftJson(options =>
~>    options.SerializerSettings.TypeNameHandling = TypeNameHandling.All);
var app = builder.Build();
app.MapControllers();
app.Run();
