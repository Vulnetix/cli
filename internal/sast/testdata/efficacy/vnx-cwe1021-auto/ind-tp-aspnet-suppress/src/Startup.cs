using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Portal
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            services.AddAntiforgery(options =>
            {
                options.HeaderName = "X-CSRF";
~>                options.SuppressXFrameOptionsHeader = true;
            });
        }
    }
}
