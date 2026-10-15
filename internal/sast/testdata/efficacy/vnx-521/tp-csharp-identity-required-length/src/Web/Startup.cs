using Microsoft.AspNetCore.Identity;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.Configure<IdentityOptions>(options =>
        {
            options.Password.RequireDigit = false;
~>            options.Password.RequiredLength = 4;
            options.Lockout.MaxFailedAccessAttempts = 5;
        });
    }

    public bool Weak(string password)
    {
~>        return password.Length < 6;
    }
}
