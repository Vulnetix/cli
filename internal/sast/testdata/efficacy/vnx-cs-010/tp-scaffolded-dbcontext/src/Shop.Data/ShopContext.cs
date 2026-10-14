using Microsoft.EntityFrameworkCore;

namespace Shop.Data
{
    public partial class ShopContext : DbContext
    {
        public virtual DbSet<Product> Products { get; set; } = null!;

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
#warning To protect potentially sensitive information in your connection string, you should move it out of source code.
~>                optionsBuilder.UseSqlServer("Server=tcp:shop.database.windows.net,1433;Initial Catalog=Shop;User ID=shopadmin;Password=Sh0p-Adm1n;Encrypt=True;");
            }
        }
    }

    public class Product
    {
        public int Id { get; set; }
        public string Name { get; set; } = "";
    }

    public class AuditContext : DbContext
    {
        protected override void OnConfiguring(DbContextOptionsBuilder options) =>
~>            options.UseNpgsql("Host=audit-db;Database=audit;Username=auditor;Password=Aud1t-2023");
    }
}
