using System.Linq;
using System.Threading.Tasks;
using Dapper;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Billing
{
    public class InvoiceQueries
    {
        private readonly NpgsqlConnection _conn;
        private readonly BillingContext _db;

        public InvoiceQueries(NpgsqlConnection conn, BillingContext db)
        {
            _conn = conn;
            _db = db;
        }

        public async Task<Invoice[]> ForTenantAsync(string tenantId, string sortColumn)
        {
~>            var rows = await _conn.QueryAsync<Invoice>(string.Format("SELECT * FROM invoices WHERE tenant_id = '{0}' ORDER BY {1}", tenantId, sortColumn));
            return rows.ToArray();
        }

        public int VoidInvoice(string invoiceNumber)
        {
~>            return _db.Database.ExecuteSqlRaw("UPDATE invoices SET voided = true WHERE number = '" + invoiceNumber + "'");
        }

        public Invoice[] Search(string term)
        {
            var query = $"SELECT * FROM invoices WHERE memo ILIKE '%{term}%'";
~>            return _db.Invoices.FromSqlRaw(query).AsNoTracking().ToArray();
        }
    }
}
