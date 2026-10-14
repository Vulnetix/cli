using System;
using System.Configuration;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace Web.Data
{
    public class AppDbContext : DbContext
    {
        private readonly IConfiguration _config;

        public AppDbContext(IConfiguration config) => _config = config;

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            options.UseSqlServer(_config.GetConnectionString("DefaultConnection"));
        }

        public SqlConnection Legacy()
        {
            var cs = ConfigurationManager.ConnectionStrings["Main"].ConnectionString;
            return new SqlConnection(cs);
        }

        public SqlConnection FromEnvironment()
        {
            var builder = new SqlConnectionStringBuilder(_config.GetConnectionString("Reporting"))
            {
                UserID = _config["Db:User"],
                Password = _config["Db:Password"],
            };
            builder.Password = Environment.GetEnvironmentVariable("DB_PASSWORD");
            return new SqlConnection(builder.ConnectionString);
        }

        public SqlConnection Integrated()
        {
            return new SqlConnection("Server=sql01;Database=Hr;Integrated Security=true;TrustServerCertificate=True");
        }

        public SqlConnection Managed()
        {
            return new SqlConnection("Server=tcp:hr.database.windows.net;Database=Hr;Authentication=Active Directory Managed Identity;");
        }
    }
}
