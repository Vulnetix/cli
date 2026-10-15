using Microsoft.EntityFrameworkCore;

namespace Data
{
    public class AppDbContext : DbContext
    {
        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
~>            options.UseNpgsql("Host=db;Database=shop;Username=shop;Password=changeme;");
        }
    }
}
