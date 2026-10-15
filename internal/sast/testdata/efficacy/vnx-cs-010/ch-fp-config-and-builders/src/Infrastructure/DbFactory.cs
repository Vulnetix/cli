using System;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using RabbitMQ.Client;

namespace Infrastructure
{
    public sealed class DbFactory
    {
        private readonly IConfiguration _config;

        public DbFactory(IConfiguration config)
        {
            _config = config;
        }

        public SqlConnection Open()
        {
            var csb = new SqlConnectionStringBuilder(_config.GetConnectionString("Main"))
            {
                Password = _config["Db:Password"],
            };
            return new SqlConnection(csb.ConnectionString);
        }

        public SqlConnection FromEnv()
        {
            var pwd = Environment.GetEnvironmentVariable("DB_PASSWORD");
            return new SqlConnection($"Server=sql01;Database=app;User Id=app;Password={pwd};");
        }

        public SqlConnection Concat(string secret)
        {
            return new SqlConnection("Server=sql01;Database=app;User Id=app;Password=" + secret + ";");
        }

        public SqlConnection Integrated()
        {
            return new SqlConnection("Server=sql01;Database=app;Integrated Security=true;TrustServerCertificate=True");
        }

        public IConnection Broker(string password)
        {
            var factory = new ConnectionFactory { HostName = "mq01", Password = password };
            return factory.CreateConnection();
        }

        public string Template() => "Server={0};Database={1};User Id={2};Password={3};";
    }
}
