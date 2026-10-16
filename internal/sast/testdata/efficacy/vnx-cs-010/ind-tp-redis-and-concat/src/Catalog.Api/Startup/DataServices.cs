using Microsoft.Data.SqlClient;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;

namespace Catalog.Api.Startup
{
    public static class DataServices
    {
        private static readonly string CatalogDb = "Server=10.20.4.12;Database=Catalog;" +
~>            "User Id=catalog_svc;Password=C4talog#2023;";

        public static IServiceCollection AddCatalogData(this IServiceCollection services)
        {
~>            var mux = ConnectionMultiplexer.Connect("redis-catalog.internal:6380,password=Rd5-Catalog-Key,ssl=True,abortConnect=False");
            services.AddSingleton<IConnectionMultiplexer>(mux);

            var options = new ConfigurationOptions
            {
                EndPoints = { "redis-sessions.internal:6379" },
~>                Password = "S3ssion-Cache-77",
                AbortOnConnectFail = false,
            };
            services.AddSingleton(_ => ConnectionMultiplexer.Connect(options));

            services.AddScoped(_ => new SqlConnection(CatalogDb));
            return services;
        }

        public static string Etl(string host, string db)
        {
~>            return $"Host={host};Username=etl;Password=Etl-Load-9;Database={db}";
        }
    }
}
