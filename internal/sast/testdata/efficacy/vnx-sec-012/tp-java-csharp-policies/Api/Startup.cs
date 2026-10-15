public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddCors(options =>
        {
            options.AddPolicy("open", policy =>
~>                policy.SetIsOriginAllowed(_ => true)
                      .AllowCredentials()
                      .AllowAnyHeader());
            options.AddPolicy("any", policy =>
~>                policy.AllowAnyOrigin().AllowAnyMethod());
        });
    }
}
