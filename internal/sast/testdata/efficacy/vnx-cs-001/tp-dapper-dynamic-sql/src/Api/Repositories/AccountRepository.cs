using System.Collections.Generic;
using System.Data;
using System.Threading.Tasks;
using Dapper;

namespace Api.Repositories
{
    public class AccountRepository
    {
        private readonly IDbConnection _conn;

        public AccountRepository(IDbConnection conn) => _conn = conn;

        public Account Find(string login)
        {
~>            return _conn.QueryFirstOrDefault<Account>("SELECT * FROM Accounts WHERE Login = '" + login + "'");
        }

        public async Task<IEnumerable<Order>> Orders(string status)
        {
            var sql = $"SELECT * FROM Orders WHERE Status = '{status}'";
~>            return await _conn.QueryAsync<Order>(sql);
        }

        public int Close(string accountId)
        {
~>            return _conn.Execute($"UPDATE Accounts SET Closed = 1 WHERE Id = '{accountId}'");
        }
    }
}
