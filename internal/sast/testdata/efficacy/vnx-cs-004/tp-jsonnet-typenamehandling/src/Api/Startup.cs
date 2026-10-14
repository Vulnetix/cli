using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;

namespace Api
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers().AddNewtonsoftJson(o =>
~>                o.SerializerSettings.TypeNameHandling = TypeNameHandling.Auto);

            JsonConvert.DefaultSettings = () => new JsonSerializerSettings
            {
~>                TypeNameHandling = TypeNameHandling.Objects,
            };
        }
    }
}
