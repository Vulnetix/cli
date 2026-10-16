using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;

namespace Api
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers()
                .AddNewtonsoftJson(options =>
                {
~>                    options.SerializerSettings.TypeNameHandling = TypeNameHandling.Auto;
                    options.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
                });
        }
    }
}
