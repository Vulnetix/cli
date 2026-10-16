using Microsoft.EntityFrameworkCore;

namespace Orders.Data
{
    public partial class OrdersContext : DbContext
    {
        public OrdersContext()
        {
        }

        public OrdersContext(DbContextOptions<OrdersContext> options)
            : base(options)
        {
        }

        public virtual DbSet<Order> Orders { get; set; } = null!;

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
#warning To protect potentially sensitive information in your connection string, you should move it out of source code.
~>                optionsBuilder.UseSqlServer("Server=tcp:orders-prod.database.windows.net,1433;Initial Catalog=Orders;Persist Security Info=False;User ID=ordersadmin;Password=Ord3rs!Prod2022;MultipleActiveResultSets=False;Encrypt=True;");
            }
        }
    }
}
