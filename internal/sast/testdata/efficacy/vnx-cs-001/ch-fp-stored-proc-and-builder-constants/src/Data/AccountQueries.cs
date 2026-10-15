using System.Data;
using System.Data.SqlClient;
using System.Text;
using Microsoft.EntityFrameworkCore;

namespace Bank.Data
{
    public class AccountQueries
    {
        public SqlDataReader Balance(SqlConnection conn, int accountId)
        {
            var cmd = new SqlCommand("dbo.GetBalance", conn) { CommandType = CommandType.StoredProcedure };
            cmd.Parameters.AddWithValue("@AccountId", accountId);
            return cmd.ExecuteReader();
        }

        public SqlDataReader History(SqlConnection conn, int accountId, bool onlyCredits)
        {
            var sb = new StringBuilder();
            sb.Append("SELECT Amount, PostedAt FROM Ledger");
            sb.Append(" WHERE AccountId = @AccountId");
            if (onlyCredits)
            {
                sb.Append(" AND Amount > 0");
            }
            var cmd = new SqlCommand(sb.ToString(), conn);
            cmd.Parameters.Add("@AccountId", SqlDbType.Int).Value = accountId;
            return cmd.ExecuteReader();
        }

        public Task<List<Account>> ByOwner(BankContext db, string owner)
        {
            return db.Accounts.FromSqlRaw("SELECT * FROM Accounts WHERE Owner = {0}", owner).ToListAsync();
        }

        public Task<int> Close(BankContext db, int id)
        {
            return db.Database.ExecuteSqlInterpolatedAsync($"UPDATE Accounts SET Closed = 1 WHERE Id = {id}");
        }
    }
}
