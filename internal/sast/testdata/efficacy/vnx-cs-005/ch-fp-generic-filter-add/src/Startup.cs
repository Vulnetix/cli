using Microsoft.AspNetCore.Mvc;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddMvc(options => options.Filters.Add<AutoValidateAntiforgeryTokenAttribute>());
    }
}
